package ssproxy

import (
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net"
)

type ProxyConn struct {
	net.Conn
	version SocksVersion
	method  AuthMethod
}

func NewProxyConn(conn net.Conn) *ProxyConn {
	return &ProxyConn{Conn: conn, method: AuthMethodNotRequired}
}

func (c *ProxyConn) Handshake(methods ...AuthMethod) error {

	// 通过第一个字节来识别是哪种socks协议版本
	buf := make([]byte, 1)

	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}

	switch buf[0] {
	case uint8(Socks4Version):
	case uint8(Socks5Version):
		return c.buildSocks5(methods...)
	default:
		return ErrVer

	}
	return nil
}

func (c *ProxyConn) Authenticate(handle PasswordHandle) error {
	if c.method != AuthMethodUsernamePassword {
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
	if _, err := io.ReadFull(c, header[:2]); err != nil {
		return err
	}

	// 只支持第一版
	if header[0] != AuthUsernamePasswordVersion {
		return fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// 获取用户名
	userLen := int(header[1])

	if _, err := io.ReadFull(c, header[2:userLen+2]); err != nil {
		return err
	}

	// 获取密码的长度
	if _, err := io.ReadFull(c, header[2+userLen:2+userLen+1]); err != nil {
		return err
	}

	// 获取密码
	passLen := int(header[2+userLen])

	if _, err := io.ReadFull(c, header[2+userLen+1:3+userLen+passLen]); err != nil {
		return err
	}

	user := string(header[2 : userLen+2])
	password := string(header[2+userLen+1 : 3+userLen+passLen])

	pass, err := handle(user)
	if err != nil {
		return err
	}
	if pass == password {
		if _, err := c.Write([]byte{AuthUsernamePasswordVersion, AuthStatusSucceeded}); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("username or password is incorrect")
}

func (c *ProxyConn) buildSocks5(methods ...AuthMethod) error {

	buf := make([]byte, 256)
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     |  1~255   |
	//+----+----------+----------+
	if _, err := io.ReadFull(c, buf[0:1]); err != nil {
		return err
	}

	methodLen := int(buf[0])

	if methodLen == 0 {
		return ErrAuthExtraData
	}
	// 根据method的大小读取接下来的字节
	if _, err := io.ReadFull(c, buf[1:methodLen+1]); err != nil {
		return err
	}
	if len(methods) == 0 {
		methods = []AuthMethod{AuthMethodNotRequired}
	}

	for _, char := range buf[1:] {
		if AuthMethod(char) == methods[0] {
			c.method = methods[0]
			break
		}
	}
	//+----+--------+
	//|VER | METHOD |
	//+----+--------+
	//| 1  |   1    |
	//+----+--------+
	_, err := c.Write([]byte{uint8(Socks5Version), uint8(c.method)})
	if err != nil {
		return err
	}

	return nil
}

func (c *ProxyConn) buildSock4() error {

	return nil
}
