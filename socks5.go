package ssproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lifei6671/ssproxy/logs"
	"golang.org/x/time/rate"
	"io"
	"net"
	"time"
)

type Socks5Conn struct {
	method AuthMethod
	net.Conn
	limiter *rate.Limiter
}

// NewSocks5Conn 初始化一个socks5协议的连接，并指定支持的认证方式
func NewSocks5Conn(conn net.Conn, method AuthMethod) *Socks5Conn {
	c := &Socks5Conn{Conn: conn, method: method}
	return c
}

// Handshake 握手阶段
func (conn *Socks5Conn) Handshake() error {
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     |  1~255   |
	//+----+----------+----------+
	// 客户端请求的协议格式
	buf := make([]byte, 258)

	if _, err := io.ReadFull(conn, buf[0:2]); err != nil {
		ErrorLogger.Println("读取数据失败 ->", conn.RemoteAddr(), err)
		return err
	}

	//仅支持 socks5
	if buf[0] != uint8(Socks5Version) {
		ErrorLogger.Println("协议版本不正确 ->", conn.RemoteAddr(), buf[0])
		return ErrVer
	}

	methodLen := int(buf[1])
	//如果读取到的认证方式为0则说明非socks5协议
	if methodLen <= 0 {
		ErrorLogger.Println("解析认证方式长度失败 ->", conn.RemoteAddr(), buf[1])
		return ErrAuthExtraData
	}

	//读取客户端支持的认证方式
	if _, err := io.ReadFull(conn, buf[2:methodLen+2]); err != nil {
		return err
	}

	for _, char := range buf[2:] {
		//命中了支持的认证方式直接响应客户端
		if AuthMethod(char) == conn.method {
			//+----+--------+
			//|VER | METHOD |
			//+----+--------+
			//| 1  |   1    |
			//+----+--------+
			_, err := conn.Write([]byte{uint8(Socks5Version), char})
			if err != nil {
				ErrorLogger.Println("响应客户端认证方式时出错 ->", conn.RemoteAddr(), err)
				return err
			}

			return nil
		}
	}
	GeneralLogger.Println("不支持的认证方式 ->", buf[2:])
	//如果没有命中认证方式
	_, err := conn.Write([]byte{uint8(Socks5Version), uint8(AuthMethodNoAcceptableMethods)})
	if err != nil {
		return err
	}
	return nil
}

// Authenticate 如果是用户名认证，则需要调用该方法进行认证
func (conn *Socks5Conn) Authenticate(handle PasswordHandle) error {
	if conn.method != AuthMethodUsernamePassword {
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
	if _, err := io.ReadFull(conn, header[:2]); err != nil {
		return err
	}

	// 只支持第一版
	if header[0] != AuthUsernamePasswordVersion {
		return fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// 获取用户名
	userLen := int(header[1])

	if _, err := io.ReadFull(conn, header[2:userLen+2]); err != nil {
		return err
	}

	// 获取密码的长度
	if _, err := io.ReadFull(conn, header[2+userLen:2+userLen+1]); err != nil {
		return err
	}

	// 获取密码
	passLen := int(header[2+userLen])

	if _, err := io.ReadFull(conn, header[2+userLen+1:3+userLen+passLen]); err != nil {
		return err
	}

	user := string(header[2 : userLen+2])
	password := string(header[2+userLen+1 : 3+userLen+passLen])

	pass, err := handle(user)
	if err != nil {
		return err
	}
	if pass == password {
		if _, err := conn.Write([]byte{AuthUsernamePasswordVersion, AuthStatusSucceeded}); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("username or password is incorrect")
}

func (conn *Socks5Conn) Forward() error {
	// +----+-----+-------+------+----------+--------+
	// |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+--------+
	// |  1 |  1  |X’00’|  1   | Variable |     2    |
	// +----+-----+-------+------+----------+--------+
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		ErrorLogger.Println("illegal request", err)
		return err
	}

	//仅支持 socks5
	if header[0] != 0x05 {
		_, _ = conn.replayClient(0x01)
		GeneralLogger.Println("不支持的协议版本 ->", header)
		return ErrVer
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
		_, _ = conn.replayClient(0x07)
		GeneralLogger.Println("不支持的 CMD 命令 ->", cmd)
		return ErrCmd
	}

	var ip net.IP
	var fqdn string

	switch header[3] {
	case AddrTypeIPv4: //ipv4
		ipv4 := make(net.IP, net.IPv4len)
		if _, err := conn.Read(ipv4); err != nil {
			ErrorLogger.Println("read socks addr ipv4 error ", err)
			return err
		}
		ip = ipv4
	case AddrTypeFQDN: //domain
		var domainLen uint8
		//读出域名长度
		if err := binary.Read(conn, binary.BigEndian, &domainLen); err != nil {
			ErrorLogger.Println("read socks addr domain length error ", err)
			return err
		}
		domain := make([]byte, domainLen)
		if _, err := conn.Read(domain); err != nil {
			ErrorLogger.Println("read socks addr domain error ", err)
			return err
		}
		fqdn = string(domain)
	case AddrTypeIPv6: //ipv6
		ipv6 := make(net.IP, net.IPv6len)
		if _, err := conn.Read(ipv6); err != nil {
			ErrorLogger.Println("read socks addr ipv6 error ", err)
			return err
		}
		ip = ipv6
	default:
		if _, err := conn.replayClient(0x08); err != nil {
			return err
		}
		return ErrUnrecognizedAddrType
	}
	var port uint16
	if err := binary.Read(conn, binary.BigEndian, &port); err != nil {
		ErrorLogger.Println("read socks port error ", err)
		if _, err := conn.Write([]byte{uint8(Socks5Version), 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
			ErrorLogger.Println("写入客户端失败 ->", conn.RemoteAddr(), err)
			return err
		}
		return err
	}
	var addr string
	if fqdn != "" {
		addr = fmt.Sprintf("%s:%d", fqdn, port)

	} else {
		addr = fmt.Sprintf("%s:%d", ip.String(), port)
	}

	GeneralLogger.Println("解析代理目标地址成功 ->", addr)
	GeneralLogger.Printf("开始连接远程服务器 -> %s ---> %s", conn.RemoteAddr(), addr)
	remoteConn, err := net.DialTimeout("tcp", addr, time.Second*30)

	if err != nil {
		ErrorLogger.Println("连接远程服务器失败 ->", addr, err)
		if _, err := conn.replayClient(0x03); err != nil {
			ErrorLogger.Println("写入客户端失败 ->", conn.RemoteAddr(), err)
		}
		return err
	}
	defer safeClose(remoteConn)
	//+----+-----+-------+------+----------+----------+
	//|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//+----+-----+-------+------+----------+----------+
	//| 1  |  1  |   1   |  1   | Variable |    2     |
	//+----+-----+-------+------+----------+----------+
	// 连接成功后返回给客户端消息
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
	if _, err := conn.replayClient(uint8(StatusSucceeded)); err != nil {
		ErrorLogger.Println("写入客户端失败 ->", conn.RemoteAddr(), err)
		return err
	}
	defer func() {
		logs.Info("正在关闭远程服务器连接 ->", remoteConn.LocalAddr())
		safeClose(remoteConn)
	}()

	GeneralLogger.Printf("开始转换数据 -> %s ---> %s", conn.RemoteAddr(), remoteConn.RemoteAddr())

	go func() {
		if _, err := Pipe(remoteConn, conn, nil); err != nil {
			ErrorLogger.Println("数据转换时出错 ->", err)
		}
	}()
	if _, err := Pipe(conn, remoteConn, nil); err != nil {
		ErrorLogger.Println("数据转换时出错 ->", err)
	}

	return nil
}

func (conn *Socks5Conn) replayClient(state byte) (int, error) {
	n, err := conn.Write([]byte{uint8(Socks5Version), 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		ErrorLogger.Println("写入客户端失败 ->", conn.RemoteAddr(), err)
	}
	return n, err
}

// SetRateLimit 设置网速
func (conn *Socks5Conn) SetRateLimit(bytesPerSec float64) {
	conn.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), BurstLimit)
	conn.limiter.AllowN(time.Now(), BurstLimit) // spend initial burst
}

func (conn *Socks5Conn) Write(p []byte) (int, error) {
	if conn.limiter == nil {
		return conn.Conn.Write(p)
	}
	n, err := conn.Conn.Write(p)
	if err != nil {
		return n, err
	}
	if err := conn.limiter.WaitN(context.Background(), n); err != nil {
		return n, err
	}
	return n, err
}
