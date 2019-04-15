package ssproxy

import (
	"context"
	"golang.org/x/time/rate"
	"net"
)

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
)

type ProxyServer struct {
	ctx     context.Context
	cancel  func()
	limiter *rate.Limiter
}

func (p *ProxyServer) Listen(network, address string) error {

	l, err := net.Listen(network, address)
	if err != nil {
		ErrorLogger.Println("启动监听失败 ->", err)
		return err
	}
	for {
		select {
		case <-p.ctx.Done():
			return nil
		default:
		}
		conn, err := l.Accept()
		if err != nil {
			ErrorLogger.Println("接受请求失败 ->", err)
			continue
		}
		go func() {
			defer func() {
				GeneralLogger.Println("正在关闭请求 ->", conn.RemoteAddr())
				if err := conn.Close(); err != nil {
					ErrorLogger.Println("关闭请求失败 ->", err)
				}
			}()
			if err := p.doProxy(conn); err != nil {
				ErrorLogger.Println("处理请求失败 ->", err)
			}
		}()
	}
}

func (p *ProxyServer) doProxy(conn net.Conn) error {

	return nil
}
