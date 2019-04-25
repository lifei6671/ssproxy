package ssproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/lifei6671/ssproxy/logs"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type (
	ProxyConfig struct {
		Listen    string                 `toml:"listen" json:"listen"`
		GFWList   string                 `toml:"gfw_list" json:"gfw_list"`
		GFWProxy  []string               `toml:"gfw_proxy" json:"gfw_proxy"`
		Proxy     map[string]ProxyTunnel `toml:"proxy" json:"proxy"`
		Rules     map[string]ProxyRule   `toml:"rule" json:"rule"`
		Blacklist []string               `toml:"blacklist" json:"blacklist"`
	}
	ProxyTunnel struct {
		Name     string `toml:"name" json:"name"`
		Type     string `toml:"type" json:"type"`
		Addr     string `toml:"addr" json:"addr"`
		UserName string `toml:"username" json:"username"`
		Password string `toml:"password" json:"password"`
	}
	ProxyRule struct {
		//规则类型：默认 HostWildcardCondition 规则统配，HostRegexCondition：域名正则
		ConditionType string   `toml:"condition_type" json:"condition_type"`
		Pattern       []string `toml:"pattern" json:"pattern"`
	}
	ProxyRoute struct {
		Rule    *Rule
		Channel map[string]*ProxyTunnel
	}
)

func (p *ProxyConfig) String() string {
	if p == nil {
		return ""
	}
	buf := bytes.NewBufferString("")

	if err := toml.NewEncoder(buf).Encode(p); err == nil {
		return buf.String()
	}
	return ""
}

func (tunnel *ProxyTunnel) String() string {
	return fmt.Sprintf("name:%s - addr:%s - type:%s - username:%s", tunnel.Name, tunnel.Addr, tunnel.Type, tunnel.UserName)
}

func (proxy *ProxyRoute) String() string {
	if proxy == nil {
		return ""
	}
	b, err := json.Marshal(proxy)
	if err != nil {
		return ""
	}
	return string(b)
}

// Resolve 解析白名单
func (p *ProxyConfig) Resolve() (map[string]*ProxyRoute, error) {
	routes := make(map[string]*ProxyRoute)

	if p.GFWList != "" && len(p.GFWProxy) > 0 {
		gfwProxy := make(map[string]*ProxyTunnel)

		for _, s := range p.GFWProxy {
			if tunnel, ok := p.Proxy[s]; ok {
				gfwProxy[tunnel.Name] = &tunnel
			}
		}
		if len(gfwProxy) <= 0 {
			goto CustomRule
		}
		resp, err := http.Get(p.GFWList)

		if err != nil {
			logs.Error("获取 GFW 规则失败 ->", err)
			return nil, err
		}
		defer safeClose(resp.Body)
		decoder := base64.NewDecoder(base64.StdEncoding, resp.Body)

		reader := bufio.NewReader(decoder)

		rules, err := ParseRules(reader)

		if err != nil {
			return nil, err
		}

		for _, rule := range rules {
			if route, ok := routes[rule.Raw]; ok {
				for k, v := range gfwProxy {
					route.Channel[k] = v
				}
			} else {
				routes[rule.Raw] = &ProxyRoute{
					Rule:    rule,
					Channel: gfwProxy,
				}
			}
		}
	}
	goto CustomRule
CustomRule:
	for name, rule := range p.Rules {
		if len(rule.Pattern) <= 0 {
			continue
		}
		proxy, ok := p.Proxy[name]

		if !ok {
			logs.Warn("代理不存在 ->", name)
			continue
		}

		for _, pattern := range rule.Pattern {
			if rule, err := ParseRule(pattern); err == nil {
				if route, ok := routes[rule.Raw]; ok {
					route.Channel[proxy.Name] = &proxy
				} else {
					routes[rule.Raw] = &ProxyRoute{
						Rule:    rule,
						Channel: map[string]*ProxyTunnel{proxy.Name: &proxy},
					}
				}
			} else {
				logs.Warn("解析规则失败 ->", err)
			}
		}
	}

	return routes, nil
}

// ResolveBlacklist 解析黑名单
func (p *ProxyConfig) ResolveBlacklist() ([]*Rule, error) {
	rules := make([]*Rule, 0, len(p.Blacklist))

	for _, s := range p.Blacklist {
		rule, err := ParseRule(s)
		if err != nil {
			logs.Error("解析规则失败 ->", s, err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// DialTimeout 连接到远程代理，并设置超时时间
func (tunnel *ProxyTunnel) DialTimeout(network string, address string, timeout time.Duration) (conn net.Conn, err error) {
	switch tunnel.Type {
	case "socks5":
		return tunnel.connectSocks5(network, address, timeout)
	case "ss", "shodowsocks":
		return tunnel.connectShadowSocks(address, timeout)
	}
	return nil, ErrNoSupportedProxyType
}

func (tunnel *ProxyTunnel) connectSocks5(network string, address string, timeout time.Duration) (conn net.Conn, err error) {
	conn, err = net.DialTimeout(network, tunnel.Addr, timeout)
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

	domain, portStr, err := net.SplitHostPort(address)

	if err != nil {
		safeClose(conn)
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		safeClose(conn)
		return nil, err
	}
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

// connectShadowSocks 连接到远程 SS 服务器
func (tunnel *ProxyTunnel) connectShadowSocks(address string, timeout time.Duration) (net.Conn, error) {

	cipher, err := ss.NewCipher(tunnel.UserName, tunnel.Password)
	if err != nil {
		logs.Error("ss.NewCipher failed:", err)
		return nil, err
	}
	ra, err := ss.RawAddr(address)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", tunnel.Addr, timeout)
	if err != nil {
		return nil, err
	}
	c := ss.NewConn(conn, cipher)
	if _, err = c.Write(ra); err != nil {
		safeClose(c)
		return nil, err
	}
	return c, nil
}
