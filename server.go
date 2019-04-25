package ssproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/lifei6671/ssproxy/logs"
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

type ProxyServer struct {
	done         <-chan struct{}
	cancel       func()
	limiter      *rate.Limiter
	Authenticate PasswordHandle
	tunnel       *sync.Map
	rule         *RuleMatcher
	blacklist    *RuleMatcher
	ruleId       int32
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	closed       bool
	defaultProxy *ProxyTunnel
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{tunnel: &sync.Map{}, rule: NewMatcher(), blacklist: NewMatcher()}
}

func (p *ProxyServer) SetDeadline(duration time.Duration) *ProxyServer {
	if p.closed {
		panic(ErrProxyClosed)
	}
	p.ReadTimeout = duration
	p.WriteTimeout = duration
	return p
}

func (p *ProxyServer) AddRule(route *ProxyRoute) error {
	if p.closed {
		return ErrProxyClosed
	}
	ruleId := int(atomic.AddInt32(&(p.ruleId), 1))
	if _, ok := p.tunnel.Load(ruleId); ok {
		logs.Debug("Rule Id 已被使用 ->", ruleId)
	}
	p.tunnel.Store(ruleId, route)
	return p.rule.AddRule(route.Rule, ruleId)
}

// AddBlack 增加一条黑名单规则
func (p *ProxyServer) AddBlack(rule *Rule) error {
	if p.closed {
		return ErrProxyClosed
	}
	ruleId := int(atomic.AddInt32(&(p.ruleId), 1))
	return p.blacklist.AddRule(rule, ruleId)
}

func (p *ProxyServer) SetDefaultProxy(tunnel *ProxyTunnel) {
	p.defaultProxy = tunnel
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
			return err
		}
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
		_, _ = Pipe(peer, c, nil)
	}()
	_, _ = Pipe(c, peer, nil)
	return nil
}

// buildHttpRequest 处理普通  HTTP 代理请求
func (p *ProxyServer) buildHttpRequest(reader *bufio.Reader, local net.Conn) (net.Conn, error) {
	req, err := http.ReadRequest(reader)

	if err != nil {
		logs.Errorf("读取请求失败 -> %s %s", local.RemoteAddr(), err)
		return nil, err
	}
	if req.RequestURI == "http://ssproxy/proxy.pac" {

	} else if req.RequestURI == "http://ssproxy/android.pac" {

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

// buildHttpConnectRequest 处理 https 发起的 connect 连接
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
			logs.Error("写入客户端失败 ->", local.RemoteAddr(), err)
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
	logs.Infof("通过 Socks 方式连接 -> %s ---> %s:%d", local.RemoteAddr(), addr, port)
	conn, err := p.selectSuperiorProxy(addr, port, addr)

	if err != nil {
		logs.Errorf("连接远程服务器失败 -> %s:%d", addr, port)
		if _, err := p.replaySocks5Client(local, 0x03); err != nil {
			ErrorLogger.Printf("写入客户端失败 -> %s:%d - %s", addr, port, err)
		}
		return nil, err
	}
	if _, err := p.replaySocks5Client(local, uint8(StatusSucceeded)); err != nil {
		logs.Errorf("写入客户端失败 ->%s %v", conn.RemoteAddr(), err)
		safeClose(conn)
		return nil, err
	}

	return conn, nil
}

// selectSuperiorProxy 选中一个远程代理
func (p *ProxyServer) selectSuperiorProxy(domain string, port uint16, rawurl string) (conn net.Conn, err error) {

	host := fmt.Sprintf("%s:%v", domain, port)
	if rawurl != "" {
		req := &Request{
			URL: rawurl,
		}
		if matched, ruleId, _ := p.blacklist.Match(req); matched {
			logs.Warnf("匹配到黑名单 -> Addr:%s;RuleId: %d", rawurl, ruleId)
			return nil, ErrDomainForbidConnect
		}
		matched, ruleId, err1 := p.rule.Match(req)

		if err1 != nil {
			logs.Error("匹配规则失败 ->", rawurl, err)
		} else if matched {
			if v, ok := p.tunnel.Load(ruleId); ok {
				if value, ok := v.(*ProxyRoute); ok {
					if len(value.Channel) > 0 {
						for _, proxy := range value.Channel {
							logs.Infof("通过远程代理[%s]连接服务器 -> %s --> %s", proxy.Addr, rawurl, proxy)
							conn, err = proxy.DialTimeout("tcp", host, time.Second*5)
							if err != nil {
								//如果连接超时，则继续下一个代理
								if err1, ok := err.(net.Error); ok && err1.Timeout() {
									logs.Warn("代理连接超时 ->", proxy.String())
									continue
								}
								return
							} else {
								return
							}
						}
						logs.Warn("所有代理都连接失败 ->", rawurl)
					}
				}
			}
		}
	}

	conn, err = net.DialTimeout("tcp", host, time.Second*5)

	if err != nil {
		if err1, ok := err.(net.Error); ok && err1.Timeout() && p.defaultProxy != nil {
			logs.Warn("远程服务器连接超时 ->", host)
			conn, err = p.defaultProxy.DialTimeout("tcp", host, time.Second*5)
		} else {
			logs.Errorf("远程服务器连接错误 -> %s;%v", host, err)
		}
	}
	return
}

func (p *ProxyServer) replaySocks5Client(conn net.Conn, state byte) (int, error) {
	n, err := conn.Write([]byte{uint8(Socks5Version), state, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		logs.Error("写入客户端失败 ->", conn.RemoteAddr(), err)
	}
	return n, err
}

// Close 关闭代理服务
func (p *ProxyServer) Close() error {
	if !p.closed {
		if p.cancel != nil {
			p.cancel()
		}
		p.closed = true
		return nil
	}
	return ErrProxyClosed
}
