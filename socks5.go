package ssproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type Socks5Conn struct {
	method AuthMethod
	net.Conn
	log Logger
}

// NewSocks5Conn 初始化一个socks5协议的连接，并指定支持的认证方式
func NewSocks5Conn(conn net.Conn, method AuthMethod) *Socks5Conn {
	c := &Socks5Conn{Conn: conn, method: method}
	return c
}

// Handshake 握手阶段
func (s *Socks5Conn) Handshake() error {
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     |  1~255   |
	//+----+----------+----------+
	// 客户端请求的协议格式
	buf := make([]byte, 258)

	if _, err := io.ReadFull(s, buf[0:2]); err != nil {
		return err
	}

	//仅支持 socks5
	if buf[0] != uint8(Socks5Version) {
		return ErrVer
	}

	methodLen := int(buf[1])
	//如果读取到的认证方式为0则说明非socks5协议
	if methodLen <= 0 {
		return ErrAuthExtraData
	}

	//读取客户端支持的认证方式
	if _, err := io.ReadFull(s, buf[2:methodLen+2]); err != nil {
		return err
	}

	for _, char := range buf[2:] {
		//命中了支持的认证方式直接响应客户端
		if AuthMethod(char) == s.method {
			//+----+--------+
			//|VER | METHOD |
			//+----+--------+
			//| 1  |   1    |
			//+----+--------+
			_, err := s.Write([]byte{uint8(Socks5Version), char})
			if err != nil {
				return err
			}

			return nil
		}
	}
	//如果没有命中认证方式
	_, err := s.Write([]byte{uint8(Socks5Version), uint8(AuthMethodNoAcceptableMethods)})
	if err != nil {
		return err
	}
	return nil
}

// Authenticate 如果是用户名认证，则需要调用该方法进行认证
func (s *Socks5Conn) Authenticate(handle PasswordHandle) error {
	if s.method != AuthMethodUsernamePassword {
		return nil
	}
	if handle == nil {
		return errors.New("需要提供一个获取密码的方法")
	}
	//+----+---------+----------+--------------+-----------+
	//|VER | USERLEN |  USER    | PASSWORD LEN | PASSWORD  |
	//+----+---------+----------+--------------+-----------+
	//| 1  |   1     |   1~255  |       1      |   1~255   |
	//+----+---------+----------+--------------+-----------+
	// 获取用户名的长度
	header := make([]byte, 513)
	if _, err := io.ReadFull(s, header[:2]); err != nil {
		return err
	}

	// 只支持第一版
	if header[0] != AuthUsernamePasswordVersion {
		return fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// 获取用户名
	userLen := int(header[1])

	if _, err := io.ReadFull(s, header[2:userLen+2]); err != nil {
		return err
	}

	// 获取密码的长度
	if _, err := io.ReadFull(s, header[2+userLen:2+userLen+1]); err != nil {
		return err
	}

	// 获取密码
	passLen := int(header[2+userLen])

	if _, err := io.ReadFull(s, header[2+userLen+1:3+userLen+passLen]); err != nil {
		return err
	}

	user := string(header[2 : userLen+2])
	password := string(header[2+userLen+1 : 3+userLen+passLen])

	pass, err := handle(user)
	if err != nil {
		return err
	}
	if pass == password {
		if _, err := s.Write([]byte{AuthUsernamePasswordVersion, AuthStatusSucceeded}); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("username or password is incorrect")
}

func (s *Socks5Conn) Forward() error {
	// +----+-----+-------+------+----------+--------+
	// |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+--------+
	// |  1 |  1  |X’00’|  1   | Variable |     2    |
	// +----+-----+-------+------+----------+--------+
	header := make([]byte, 4)

	if _, err := io.ReadFull(s, header); err != nil {
		s.log.Println("illegal request", err)
		return err
	}

	//仅支持 socks5
	if header[0] != 0x05 {
		if _, err := s.Write([]byte{0x05, 0x01}); err != nil {
			return err
		}
		s.log.Println(header)
		return ErrVer
	}
	// 仅支持tcp连接
	switch Command(header[1]) {
	case CmdConnect: //CONNECT
		break
	case CmdUdp: //UDP
		fallthrough
	case CmdBind: //BIND
		fallthrough
	default:
		if _, err := s.Write([]byte{0x05, 0x07}); err != nil {
			return err
		}
		return ErrCmd
	}
	cmd := header[1]
	var ip net.IP
	var fqdn string

	switch header[3] {
	case AddrTypeIPv4: //ipv4
		ipv4 := make(net.IP, net.IPv4len)
		if _, err := s.Read(ipv4); err != nil {
			s.log.Println("read socks addr ipv4 error ", err)
			return err
		}
		ip = ipv4
	case AddrTypeFQDN: //domain
		var domainLen uint8
		//读出域名长度
		if err := binary.Read(s, binary.BigEndian, &domainLen); err != nil {
			s.log.Println("read socks addr domain length error ", err)
			return err
		}
		domain := make([]byte, domainLen)
		if _, err := s.Read(domain); err != nil {
			s.log.Println("read socks addr domain error ", err)
			return err
		}
		fqdn = string(domain)
	case AddrTypeIPv6: //ipv6
		ipv6 := make(net.IP, net.IPv6len)
		if _, err := s.Read(ipv6); err != nil {
			s.log.Println("read socks addr ipv6 error ", err)
			return err
		}
		ip = ipv6
	default:
		return ErrUnrecognizedAddrType
	}
	var port uint16
	if err := binary.Read(s, binary.BigEndian, &port); err != nil {
		s.log.Println("read socks port error ", err)
		return err
	}
	var addr string
	if fqdn != "" {
		s.log.Println("resolve domain ", fqdn)
		addr = fmt.Sprintf("%s:%d", fqdn, port)

	} else {
		addr = fmt.Sprintf("%s:%d", ip.String(), port)
	}

	remoteConn, err := net.Dial("tcp", addr)

	if err != nil {
		return err
	}

	return nil
}
