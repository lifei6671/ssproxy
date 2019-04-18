package ssproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

//需要处理服务器端无法解析的请求头
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

type (
	Socks5Negotiation struct {
		Version      uint8
		NumOfMethods uint8
		Methods      []uint8
	}

	Socks5Request struct {
		Version         uint8
		Command         uint8
		RSV             uint8
		AddressType     uint8
		Address         string
		Port            uint16
		AddressWithPort string
		RawAddr         []byte
	}
	ProxyTunnel struct {
		Name     string `toml:"name" json:"name"`
		Type     string `toml:"type" json:"type"`
		Addr     string `toml:"addr" json:"addr"`
		UserName string `toml:"username" json:"username"`
		Password string `toml:"password" json:"password"`
	}
)

type ProxyServer struct {
	done         <-chan struct{}
	cancel       func()
	limiter      *rate.Limiter
	Authenticate PasswordHandle
	tunnel       *sync.Map
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	closed       bool
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{tunnel: &sync.Map{}}
}

func (p *ProxyServer) SetDeadline(duration time.Duration) *ProxyServer {
	p.ReadTimeout = duration
	p.WriteTimeout = duration
	return p
}

func (p *ProxyServer) AddRouter(domain string, tunnel ProxyTunnel) *ProxyServer {

	p.tunnel.Store(domain, &tunnel)
	return p
}

// AddConnectionWrappers 增加连接的包装器
func (p *ProxyServer) AddConnectionWrappers() *ProxyServer {

	return p
}
func (p *ProxyServer) Listen(ctx context.Context, network, address string) error {

	l, err := net.Listen(network, address)
	if err != nil {
		ErrorLogger.Println("启动监听失败 ->", err)
		return err
	}
	ctx1, cancel := context.WithCancel(ctx)

	p.cancel = cancel
	go func() {
		p.done = ctx1.Done()
	}()
	GeneralLogger.Println("正在监听地址 ->", l.Addr())
	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		select {
		case <-ctx1.Done():
			return nil
		default:
		}
		conn, err := l.Accept()
		if err != nil {
			ErrorLogger.Println("接受请求失败 ->", err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				// delay code based on net/http.Server
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				ErrorLogger.Printf("http: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return fmt.Errorf("error accepting: %v", err)
		}
		go func() {
			defer safeClose(conn)
			if err := p.doProxy(conn); err != nil {
				ErrorLogger.Println("处理请求失败 ->", err)
			}
		}()
	}
}

func (p *ProxyServer) doProxy(c net.Conn) error {

	cr := bufio.NewReader(c)

	buff, err := cr.Peek(3)
	if err != nil {
		ErrorLogger.Println("识别连接类型失败 ->", err)
		return err
	}
	var peer net.Conn
	// 根据请求第一个字节判断是什么类型的代理
	// 如果发起的是HTTP代理请求
	if bytes.Equal(buff, []byte("CON")) || (buff[0] >= 'A' && buff[0] <= 'Z') {
		peer, err = p.buildHttpRequest(cr, c)
		if err != nil {
			ErrorLogger.Println("创建 HTTP  代理失败 ->", err)
			return err
		}
	} else if buff[0] == uint8(Socks5Version) {

	} else if buff[0] == uint8(Socks4Version) {

	} else {
		return fmt.Errorf("未知的协议 -> %v", buff)
	}
	if err != nil {
		ErrorLogger.Println(err)
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		localAddr, remoteAddr := c.RemoteAddr(), peer.RemoteAddr()
		GeneralLogger.Println("等待连接关闭通知 ->", localAddr, remoteAddr)
		defer func() {
			GeneralLogger.Println("连接已关闭 ->", localAddr, remoteAddr)
		}()
		select {
		case <-p.done:
			_ = peer.Close()
		case <-ctx.Done():
			_ = peer.Close()
			return
		}
	}()
	defer cancel()

	GeneralLogger.Println("正在转换数据 ->", peer.RemoteAddr(), c.RemoteAddr())
	go func() {
		_, _ = Pipe(peer, c, nil)
	}()
	_, _ = Pipe(cr, peer, nil)
	return nil
}

func (p *ProxyServer) buildHttpRequest(reader *bufio.Reader, local net.Conn) (net.Conn, error) {
	req, err := http.ReadRequest(reader)

	if err != nil {
		ErrorLogger.Printf("读取请求失败 -> %s %s", local.RemoteAddr(), err)
		return nil, err
	}
	GeneralLogger.Printf("请求 -> %s -- %s -- %s", req.Method, req.RequestURI, local.RemoteAddr())
	//如果是 Connect 连接，则直接打洞
	if req.Method == http.MethodConnect {
		return p.buildHttpConnectRequest(req, local)
	}

	outreq := req.WithContext(context.Background())
	if req.ContentLength == 0 {
		outreq.Body = nil
	}
	reqUpType := upgradeType(outreq.Header)
	removeConnectionHeaders(outreq.Header)

	//处理掉其他代理可能不识别的请求头
	for _, h := range hopHeaders {
		hv := outreq.Header.Get(h)
		if hv == "" {
			continue
		}
		if h == "Te" && hv == "trailers" {
			continue
		}
		outreq.Header.Del(h)
	}

	if reqUpType != "" {
		outreq.Header.Set("Connection", "Upgrade")
		outreq.Header.Set("Upgrade", reqUpType)
	}

	_port := outreq.URL.Port()
	//当时 80 端口是，客户端不会传输
	if _port == "" {
		_port = "80"
	}
	port, err := strconv.Atoi(_port)
	if err != nil {
		ErrorLogger.Println("解析端口号失败 ->", err)
		return nil, err
	}
	conn, err := p.selectSuperiorProxy(outreq.URL.Host, uint16(port))
	if err != nil {
		ErrorLogger.Println("连接远程服务器失败 ->", err)
		return nil, err
	}

	if err := outreq.Write(conn); err != nil {
		safeClose(conn)
		ErrorLogger.Println("写入远程信息失败 ->", err)
		return nil, err
	}
	r := bufio.NewReader(conn)

	res, err := http.ReadResponse(r, outreq)

	if err != nil {
		safeClose(conn)
		ErrorLogger.Println("获取响应失败 ->", err)
		return nil, err
	}
	//如果是 websocket 则不能断开连接直接返回即可
	if res.StatusCode == http.StatusSwitchingProtocols {
		if err := res.Write(local); err != nil {
			safeClose(conn)
			return nil, err
		}
		return conn, nil
	}
	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	if err := res.Write(local); err != nil {
		safeClose(conn)
		return nil, err
	}
	// 如果正确的处理了 Proxy-Connection  请求头，则不需要关闭连接，客户端会复用
	return conn, nil
}

func (p *ProxyServer) buildHttpConnectRequest(req *http.Request, local net.Conn) (conn net.Conn, err error) {
	domain, _port, err1 := net.SplitHostPort(req.Host)
	if err1 != nil {
		ErrorLogger.Println("解析端口号失败 ->", req.Host, err1)
		_, _ = fmt.Fprintf(local, req.Proto+" 500 Connection failed, err:%s\r\n\r\n", err1)
		return nil, err1
	}
	port, err1 := strconv.Atoi(_port)
	if err != nil {
		ErrorLogger.Println("端口号格式不正确 ->", err1, _port)
		_, _ = fmt.Fprintf(local, req.Proto+" 500 Connection failed, err:%s\r\n\r\n", err1)
		return nil, err1
	}
	conn, err = p.selectSuperiorProxy(domain, uint16(port))
	if err != nil {
		ErrorLogger.Println("连接远程服务器失败 ->", err)
		_, _ = fmt.Fprintf(local, req.Proto+" 500 Connection failed, err:%s\r\n\r\n", err)
		return nil, err
	}
	GeneralLogger.Println(req.Host, req.Proto)
	_, err = local.Write([]byte(req.Proto + " 200 Connection established\r\n\r\n"))
	if err != nil {
		safeClose(conn)
		ErrorLogger.Println("响应客户端失败 ->", err)
		return nil, err
	}
	return
}

func (p *ProxyServer) selectSuperiorProxy(domain string, port uint16) (conn net.Conn, err error) {
	if ps, ok := p.tunnel.Load(domain); ok {
		if proxy, ok := ps.(*ProxyTunnel); ok {
			if proxy.Type == "socks5" {
				return p.connectSocks5Server(*proxy, domain, port)
			} else if proxy.Type == "socks4" {
				return p.connectSocks4Server(*proxy)
			} else if proxy.Type == "http" {
				return p.connectSocks4Server(*proxy)
			}
		}
	}

	return net.DialTimeout("tcp", fmt.Sprintf("%s:%v", domain, port), time.Second*30)
}

func (p *ProxyServer) connectSocks5Server(tunnel ProxyTunnel, domain string, port uint16) (conn net.Conn, err error) {

	GeneralLogger.Println("正在连接远程代理服务器 ->", tunnel.Addr)
	conn, err = net.DialTimeout("tcp", tunnel.Addr, time.Second*30)
	if err != nil {
		return nil, err
	}
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     |  1~255   |
	//+----+----------+----------+
	// 客户端请求的协议格式
	b := make([]byte, 3)
	b[0] = uint8(Socks5Version)
	b[1] = 0x01
	//如果有用户名和密码则认为是账号认证
	if tunnel.UserName != "" && tunnel.Password != "" {
		b[2] = uint8(AuthMethodUsernamePassword)
	} else {
		b[2] = uint8(AuthMethodNotRequired)
	}
	_, err = conn.Write(b)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	//+----+--------+
	//|VER | METHOD |
	//+----+--------+
	//| 1  |   1    |
	//+----+--------+
	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if b[1] == uint8(AuthMethodNoAcceptableMethods) {
		_ = conn.Close()
		return nil, ErrNoSupportedAuth
	}
	if b[1] == uint8(AuthMethodUsernamePassword) {
		auth := &UsernamePassword{Username: tunnel.UserName, Password: tunnel.Password}
		err = auth.Authenticate(conn, AuthMethodUsernamePassword)
		if err != nil {
			ErrorLogger.Println("代理认证失败 ->", conn.RemoteAddr(), err)
			_ = conn.Close()
			return nil, err
		}
	}
	// +----+-----+-------+------+----------+--------+
	// |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+--------+
	// |  1 |  1  |X’00’|  1   | Variable |     2    |
	// +----+-----+-------+------+----------+--------+
	b = []byte{uint8(Socks5Version), uint8(CmdConnect), 0x00}

	ip := net.ParseIP(domain)
	if ip == nil {
		b = append(b, AddrTypeFQDN, uint8(len(domain)))
	} else if len(ip) == 4 {
		b = append(b, AddrTypeIPv4)
	} else {
		b = append(b, AddrTypeIPv6)
	}
	b = append(b, domain...)
	index := len(b)

	b = append(b, 0, 0)
	binary.BigEndian.PutUint16(b[index:], uint16(port))

	_, err = conn.Write(b)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	//+----+-----+-------+------+----------+----------+
	//|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//+----+-----+-------+------+----------+----------+
	//| 1  |  1  |   1   |  1   | Variable |    2     |
	//+----+-----+-------+------+----------+----------+
	//- REP : 返回值
	//- 0x00 : succeeded
	//- 0x01 : general SOCKS server failure
	//- 0x02 : connection not allowed by ruleset
	//- 0x03 : Network unreachable
	//- 0x04 : Host unreachable
	//- 0x05 : Connection refused
	//- 0x06 : TTL expired
	//- 0x07 : Command not supported
	//- 0x08 : Address type not supported
	//- 0x09-0xFF : unassigned
	_, err = conn.Read(b[0:4])
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if b[0] != uint8(Socks5Version) {
		_ = conn.Close()
		return nil, ErrVer
	}

	if b[1] != 0 {
		_ = conn.Close()
		switch b[1] {
		case 1:
			return nil, errors.New("socks5 general SOCKS server failure")
		case 2:
			return nil, errors.New("socks5 connection not allowed by ruleset")
		case 3:
			return nil, errors.New("socks5 Network unreachable")
		case 4:
			return nil, errors.New("socks5 Host unreachable")
		case 5:
			return nil, errors.New("socks5 Connection refused")
		case 6:
			return nil, errors.New("socks5 TTL expired")
		case 7:
			return nil, errors.New("socks5 Command not supported")
		case 8:
			return nil, errors.New("socks5 Address type not supported")
		default:
			return nil, fmt.Errorf("socks5 Unknown eerror: %d", b[1])
		}
	}
	addrLen := 0
	switch b[3] {
	case AddrTypeFQDN:
		_, err = conn.Read(b[4:5])
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		addrLen = int(b[4])

	case AddrTypeIPv4:
		addrLen = 4
	case AddrTypeIPv6:
		addrLen = 16
	}
	_, err = conn.Read(b[4 : addrLen+4+2])
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return
}

func (p *ProxyServer) connectSocks4Server(tunnel ProxyTunnel) (conn net.Conn, err error) {
	return
}

func (p *ProxyServer) connectHttpServer(tunnel ProxyTunnel) (conn net.Conn, err error) {
	return
}

func (p *ProxyServer) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	p.closed = true
	return nil
}

func safeClose(conn net.Conn) {
	defer func() {
		p := recover()
		if p != nil {
			ErrorLogger.Printf("panic on closing connection from %v: %v", conn.RemoteAddr(), p)
		}
	}()
	_ = conn.Close()
}
