package main

import (
	"context"
	"github.com/lifei6671/ssproxy"
	"log"
	"net"
	"time"
)

func main() {
	go func() {
		l, err := net.Listen("tcp", ":1080")
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			c := ssproxy.NewSocks5Conn(conn, ssproxy.AuthMethodUsernamePassword)
			go func() {
				defer func() {
					_ = c.Close()
				}()
				if err := c.Handshake(); err != nil {
					log.Println("握手失败 ->", err)
					return
				}
				err := c.Authenticate(func(user string) (password string, err error) {
					return "123456", nil
				})
				if err != nil {
					log.Println("认证失败 ->", err)
					return
				}
				if err := c.Forward(); err != nil {
					log.Println("转发失败 ->", err)
				}

			}()
		}
	}()
	proxy := ssproxy.NewProxyServer()
	//proxy.AddRouter("www.xin.com", ssproxy.ProxyTunnel{UserName: "root", Password: "123456", Type: "socks5", Addr: "127.0.0.1:1080"})
	proxy.SetDeadline(time.Second * 30)
	proxy.AddRegexpRouter(ssproxy.ProxyTunnel{Name: "*.google.com", UserName: "aes-256-cfb", Password: "_hvolZ8H-mZ_bTar", Type: "ss", Addr: "la1533.256ss.com:32318"})

	defer func() {
		_ = proxy.Close()
	}()
	if err := proxy.Listen(context.Background(), "tcp", ":8580"); err != nil {
		log.Fatal(err)
	}
}
