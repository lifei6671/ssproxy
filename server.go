package ssproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/lifei6671/ssproxy/logs"
	"github.com/pkg/errors"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
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
var connect = []byte("CON")

type (
	ProxyTunnel struct {
		Name     string `toml:"name" json:"name"`
		Type     string `toml:"type" json:"type"`
		Addr     string `toml:"addr" json:"addr"`
		UserName string `toml:"username" json:"username"`
		Password string `toml:"password" json:"password"`
	}
)

func (proxy *ProxyTunnel) String() string {
	return fmt.Sprintf("name:%s - addr:%s - type:%s - username:%s", proxy.Name, proxy.Addr, proxy.Type, proxy.UserName)
}

type ProxyServer struct {
	done         <-chan struct{}
	cancel       func()
	limiter      *rate.Limiter
	Authenticate PasswordHandle
	tunnel       *sync.Map
	rule         *RuleMatcher
	ruleId       int32
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	closed       bool
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{tunnel: &sync.Map{}, rule: NewMatcher()}
}

func (p *ProxyServer) SetDeadline(duration time.Duration) *ProxyServer {
	p.ReadTimeout = duration
	p.WriteTimeout = duration
	return p
}

func (p *ProxyServer) AddRouter(s string, tunnel *ProxyTunnel) error {
	rule, err := ParseRule(s)
	if err != nil {
		logs.Error("解析规则失败 ->", s, err)
		return err
	}

	ruleId := int(atomic.AddInt32(&(p.ruleId), 1))
	if _, ok := p.tunnel.Load(ruleId); ok {
		logs.Debug("Rule Id 已被使用 ->", ruleId)
	}
	p.tunnel.Store(ruleId, tunnel)
	return p.rule.AddRule(rule, ruleId)
}

func (p *ProxyServer) AddRouteFromGFWList(rawurl string, tunnel *ProxyTunnel) error {
	resp, err := http.Get(rawurl)

	if err != nil {
		return err
	}
	defer safeClose(resp.Body)
	decoder := base64.NewDecoder(base64.StdEncoding, resp.Body)

	reader := bufio.NewReader(decoder)

	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err != io.EOF {
				logs.Error("读取 GFW 规则失败 ->", err)
			}
			break
		}
		if len(line) > 0 && !bytes.HasPrefix(line, []byte("!")) {
			if err := p.AddRouter(string(line), tunnel); err != nil {
				logs.Error("解析GFW规则失败 ->", string(line), err)
			}
		}
	}
	return nil
}

// AddConnectionWrappers 增加连接的包装器
func (p *ProxyServer) AddConnectionWrappers() *ProxyServer {

	return p
}

func (p *ProxyServer) Listen(ctx context.Context, network, address string) error {

	l, err := net.Listen(network, address)
	if err != nil {
		logs.Error("启动监听失败 ->", err)
		return err
	}
	ctx1, cancel := context.WithCancel(ctx)

	p.cancel = cancel
	go func() {
		p.done = ctx1.Done()
	}()
	logs.Info("正在监听地址 ->", l.Addr())
	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		select {
		case <-ctx1.Done():
			return nil
		default:
		}
		conn, err := l.Accept()
		if err != nil {
			logs.Errorf("Failed to accept new TCP connection of type %s: %v", address, err)
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
				logs.Errorf("http: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return fmt.Errorf("error accepting: %v", err)
		}
		go func() {
			defer safeClose(conn)
			if err := p.doProxy(conn); err != nil {
				logs.Error("处理请求失败 ->", err)
			}
		}()
	}
}

func (p *ProxyServer) doProxy(c net.Conn) error {

	cr := bufio.NewReader(c)

	buff, err := cr.Peek(3)
	if err != nil {
		logs.Errorf("识别连接类型失败 -> %v", err)
		return err
	}
	var peer net.Conn

	// 根据请求第一个字节判断是什么类型的代理
	// 如果发起的是HTTP代理请求
	if bytes.Equal(buff, connect) || (buff[0] >= 'A' && buff[0] <= 'Z') {
		peer, err = p.buildHttpRequest(cr, c)
		if err != nil {
			logs.Errorf("创建 HTTP  代理失败 -> %v", err)
			return err
		}
	} else if buff[0] == uint8(Socks5Version) {
		peer, err = p.buildSocksRequest(cr, c)
		if err != nil {
			ErrorLogger.Println(err)
			return err
		}
	} else if buff[0] == uint8(Socks4Version) {

	} else {
		return fmt.Errorf("未知的协议 -> %v", buff)
	}
	if peer == nil {
		logs.Errorf("未能初始化远程连接 -> %s", c.RemoteAddr())
		return fmt.Errorf("未能初始化远程连接 -> %s", c.RemoteAddr())
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		localAddr, remoteAddr := c.RemoteAddr(), peer.RemoteAddr()
		logs.Info("等待连接关闭通知 ->", localAddr, remoteAddr)
		defer func() {
			logs.Info("连接已关闭 ->", localAddr, remoteAddr)
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

	logs.Info("正在转换数据 ->", peer.RemoteAddr(), c.RemoteAddr())
	go func() {
		_, _ = NewPipeline(time.Second*30000, time.Second*30).Pipe(peer, c, nil)
	}()
	_, _ = NewPipeline(time.Second*300000, time.Second*30).Pipe(c, peer, nil)
	return nil
}

func (p *ProxyServer) buildHttpRequest(reader *bufio.Reader, local net.Conn) (net.Conn, error) {
	req, err := http.ReadRequest(reader)

	if err != nil {
		logs.Errorf("读取请求失败 -> %s %s", local.RemoteAddr(), err)
		return nil, err
	}
	logs.Infof("解析请求 -> %s -- %s -- %s", req.Method, req.RequestURI, local.RemoteAddr())
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
		logs.Error("解析端口号失败 ->", err)
		return nil, err
	}
	conn, err := p.selectSuperiorProxy(outreq.URL.Host, uint16(port), req.RequestURI)
	if err != nil {
		logs.Error("连接远程服务器失败 ->", err)
		return nil, err
	}

	if err := outreq.Write(conn); err != nil {
		safeClose(conn)
		logs.Error("写入远程信息失败 ->", err)
		return nil, err
	}
	r := bufio.NewReader(conn)

	res, err := http.ReadResponse(r, outreq)

	if err != nil {
		safeClose(conn)
		logs.Error("获取响应失败 ->", err)
		return nil, err
	}
	defer safeClose(res.Body)

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
		logs.Error("解析端口号失败 ->", req.Host, err1)
		_, _ = fmt.Fprintf(local, req.Proto+" 500 Connection failed, err:%s\r\n\r\n", err1)
		return nil, err1
	}
	port, err1 := strconv.Atoi(_port)
	if err1 != nil {
		logs.Error("端口号格式不正确 ->", err1, _port)
		_, _ = fmt.Fprintf(local, req.Proto+" 500 Connection failed, err:%s\r\n\r\n", err1)
		return nil, err1
	}
	conn, err = p.selectSuperiorProxy(domain, uint16(port), req.RequestURI)
	if err != nil {
		logs.Errorf("连接远程服务器失败 ->", err)
		_, _ = fmt.Fprintf(local, req.Proto+" 500 Connection failed, err:%s\r\n\r\n", err)
		return nil, err
	}
	_, err = local.Write([]byte(req.Proto + " 200 Connection established\r\n\r\n"))
	if err != nil {
		safeClose(conn)
		logs.Error("响应客户端失败 ->", err)
		return nil, err
	}
	return
}

// buildSocksRequest 实现接受 Socks5 连接
func (p *ProxyServer) buildSocksRequest(reader *bufio.Reader, local net.Conn) (net.Conn, error) {
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     |  1~255   |
	//+----+----------+----------+
	// 客户端请求的协议格式
	buf := bytesHeaderPool.Get().([]byte)
	defer bytesHeaderPool.Put(buf)

	if _, err := io.ReadFull(reader, buf[0:2]); err != nil {
		logs.Error("读取数据失败 ->", local.RemoteAddr(), err)
		return nil, err
	}

	//仅支持 socks5
	if buf[0] != uint8(Socks5Version) {
		logs.Error("协议版本不正确 ->", local.RemoteAddr(), buf[0])
		return nil, ErrVer
	}

	methodLen := int(buf[1])
	//如果读取到的认证方式为0则说明非socks5协议
	if methodLen <= 0 {
		logs.Error("解析认证方式长度失败 ->", local.RemoteAddr(), buf[1])
		return nil, ErrAuthExtraData
	}

	//读取客户端支持的认证方式
	if _, err := io.ReadFull(reader, buf[2:methodLen+2]); err != nil {
		return nil, err
	}
	var method AuthMethod
	isSupportAuth := false

	for i := 2; i < methodLen+2; i++ {
		//命中了支持的认证方式直接响应客户端
		if AuthMethod(buf[i]) == AuthMethodNotRequired {
			method = AuthMethodNotRequired
			isSupportAuth = true
			break
		}
	}

	if isSupportAuth {
		logs.Infof("选中的认证方式 -> %d %s", method, local.RemoteAddr())
		//如果没有命中认证方式
		_, err := local.Write([]byte{uint8(Socks5Version), uint8(method)})
		if err != nil {
			return nil, err
		}
	} else {
		logs.Infof("不支持的认证方式 -> %d %s", buf[2:], local.RemoteAddr())
		//如果没有命中认证方式
		_, err := local.Write([]byte{uint8(Socks5Version), uint8(AuthMethodNoAcceptableMethods)})
		if err != nil {
			return nil, err
		}
	}
	//进行用户认证
	if method == AuthMethodUsernamePassword {
		//+----+---------+----------+--------------+-----------+
		//|VER | USERLEN |  USER    | PASSWORD LEN | PASSWORD  |
		//+----+---------+----------+--------------+-----------+
		//| 1  |   1     |   1~255  |       1      |   1~255   |
		//+----+---------+----------+--------------+-----------+
		// 获取用户名的长度
		header := bytesHeaderPool.Get().([]byte)
		defer bytesHeaderPool.Put(header)

		if _, err := io.ReadFull(local, header[:2]); err != nil {
			return nil, err
		}

		// 只支持第一版
		if header[0] != AuthUsernamePasswordVersion {
			return nil, fmt.Errorf("unsupported auth version: %v", header[0])
		}

		// 获取用户名
		userLen := int(header[1])

		if _, err := io.ReadFull(local, header[2:userLen+2]); err != nil {
			return nil, err
		}

		// 获取密码的长度
		if _, err := io.ReadFull(local, header[2+userLen:2+userLen+1]); err != nil {
			return nil, err
		}

		// 获取密码
		passLen := int(header[2+userLen])

		if _, err := io.ReadFull(local, header[2+userLen+1:3+userLen+passLen]); err != nil {
			return nil, err
		}

		user := string(header[2 : userLen+2])
		password := string(header[2+userLen+1 : 3+userLen+passLen])

		pass, err := p.Authenticate(user)
		if err != nil {
			return nil, err
		}
		if pass == password {
			if _, err := local.Write([]byte{AuthUsernamePasswordVersion, AuthStatusSucceeded}); err != nil {
				return nil, err
			}
		} else {
			return nil, ErrUserAuthFailed
		}
	}

	// +----+-----+-------+------+----------+--------+
	// |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+--------+
	// |  1 |  1  |X’00’|  1   | Variable |     2    |
	// +----+-----+-------+------+----------+--------+
	header := bytesHeaderPool.Get().([]byte)
	defer bytesHeaderPool.Put(header)

	if _, err := io.ReadFull(reader, header[0:4]); err != nil {
		ErrorLogger.Println("illegal request", err)
		return nil, err
	}

	//仅支持 socks5
	if header[0] != 0x05 {
		_, err := local.Write([]byte{uint8(Socks5Version), 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		if err != nil {
			ErrorLogger.Println("写入客户端失败 ->", local.RemoteAddr(), err)
		}
		GeneralLogger.Println("不支持的协议版本 ->", header)
		return nil, ErrVer
	}
	cmd := Command(header[1])
	// 仅支持tcp连接
	switch cmd {
	case CmdConnect: //CONNECT
		break
	case CmdUdp: //UDP
		fallthrough
	case CmdBind: //BIND
		fallthrough
	default:
		_, err := local.Write([]byte{uint8(Socks5Version), 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		if err != nil {
			ErrorLogger.Println("写入客户端失败 ->", local.RemoteAddr(), err)
		}
		GeneralLogger.Println("不支持的 CMD 命令 ->", cmd)
		return nil, ErrCmd
	}

	var ip net.IP
	var fqdn string

	switch header[3] {
	case AddrTypeIPv4: //ipv4
		ipv4 := make(net.IP, net.IPv4len)
		if _, err := reader.Read(ipv4); err != nil {
			ErrorLogger.Println("read socks addr ipv4 error ", err)
			return nil, err
		}
		ip = ipv4
	case AddrTypeFQDN: //domain
		var domainLen uint8
		//读出域名长度
		if err := binary.Read(reader, binary.BigEndian, &domainLen); err != nil {
			ErrorLogger.Println("read socks addr domain length error ", err)
			return nil, err
		}
		domain := make([]byte, domainLen)
		if _, err := reader.Read(domain); err != nil {
			ErrorLogger.Println("read socks addr domain error ", err)
			return nil, err
		}
		fqdn = string(domain)
	case AddrTypeIPv6: //ipv6
		ipv6 := make(net.IP, net.IPv6len)
		if _, err := reader.Read(ipv6); err != nil {
			ErrorLogger.Println("read socks addr ipv6 error ", err)
			return nil, err
		}
		ip = ipv6
	default:
		if _, err := p.replaySocks5Client(local, 0x08); err != nil {
			ErrorLogger.Println("写入客户端失败 ->", local.RemoteAddr(), err)
		}
		return nil, ErrUnrecognizedAddrType
	}
	var port uint16
	if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
		ErrorLogger.Println("read socks port error ", err)
		if _, err := p.replaySocks5Client(local, 0x08); err != nil {
			ErrorLogger.Println("写入客户端失败 ->", local.RemoteAddr(), err)
		}
		return nil, err
	}
	var addr string
	if fqdn != "" {
		addr = fqdn

	} else if ip != nil {
		addr = ip.String()
	} else {
		return nil, ErrAddrType
	}
	GeneralLogger.Printf("通过 Socks 方式连接 -> %s ---> %s:%d", local.RemoteAddr(), addr, port)
	conn, err := p.selectSuperiorProxy(addr, port, addr)

	if err != nil {
		ErrorLogger.Printf("连接远程服务器失败 -> %s:%d", addr, port)
		safeClose(conn)
		if _, err := p.replaySocks5Client(local, 0x03); err != nil {
			ErrorLogger.Printf("写入客户端失败 -> %s:%d - %s", addr, port, err)
		}
		return nil, err
	}
	if _, err := p.replaySocks5Client(local, uint8(StatusSucceeded)); err != nil {
		ErrorLogger.Println("写入客户端失败 ->", conn.RemoteAddr(), err)
		safeClose(conn)
		return nil, err
	}

	return conn, nil
}

// selectSuperiorProxy 选中一个远程代理
func (p *ProxyServer) selectSuperiorProxy(domain string, port uint16, rawurl string) (conn net.Conn, err error) {
	var proxy *ProxyTunnel

	if rawurl != "" {
		req := &Request{
			URL: rawurl,
		}
		matched, ruleId, err := p.rule.Match(req)

		if err != nil {
			logs.Error("匹配规则失败 ->", rawurl, err)
		} else if matched {
			if v, ok := p.tunnel.Load(ruleId); ok {
				if value, ok := v.(*ProxyTunnel); ok {
					proxy = value
				}
			}
		}
	}

	if proxy != nil {
		logs.Infof("通过远程代理[%s]连接服务器 -> %s --> %s", proxy.Addr, rawurl, proxy)
		if proxy.Type == "socks5" {
			return p.connectSocks5Server(*proxy, domain, port)
		} else if proxy.Type == "socks4" {
			return p.connectSocks4Server(*proxy)
		} else if proxy.Type == "http" {
			return p.connectSocks4Server(*proxy)
		} else if proxy.Type == "ss" {
			return p.connectShadowsocks(fmt.Sprintf("%s:%d", domain, port), *proxy)
		}
	}
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%v", domain, port), time.Second*30)
}

func (p *ProxyServer) connectSocks5Server(tunnel ProxyTunnel, domain string, port uint16) (conn net.Conn, err error) {

	logs.Info("正在连接远程代理服务器 ->", tunnel.Addr)
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
			logs.Error("代理认证失败 ->", conn.RemoteAddr(), err)
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

func (p *ProxyServer) connectShadowsocks(rawAddr string, tunnel ProxyTunnel) (net.Conn, error) {

	cipher, err := ss.NewCipher(tunnel.UserName, tunnel.Password)
	if err != nil {
		logs.Error("ss.NewCipher failed:", err)
		return nil, err
	}

	return ss.Dial(rawAddr, tunnel.Addr, cipher.Copy())
}

func (p *ProxyServer) replaySocks5Client(conn net.Conn, state byte) (int, error) {
	n, err := conn.Write([]byte{uint8(Socks5Version), state, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		logs.Error("写入客户端失败 ->", conn.RemoteAddr(), err)
	}
	return n, err
}

func (p *ProxyServer) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	p.closed = true
	return nil
}

func safeClose(conn io.Closer) {
	defer func() {
		p := recover()
		if p != nil {
			logs.Errorf("panic on closing connection from  %v", p)
		}
	}()
	if conn != nil {
		_ = conn.Close()
	}
}
