package main

import (
	"context"
	"github.com/lifei6671/ssproxy"
	"log"
	"time"
)

func main() {

	proxy := ssproxy.NewProxyServer()
	//proxy.AddRouter("www.xin.com", ssproxy.ProxyTunnel{UserName: "root", Password: "123456", Type: "socks5", Addr: "127.0.0.1:1080"})
	proxy.SetDeadline(time.Second * 30)
	tunnel := ssproxy.ProxyTunnel{Name: "ss", UserName: "aes-256-cfb", Password: "_hvolZ8H-mZ_bTar", Type: "ss", Addr: "la1533.256ss.com:32318"}
	if err := proxy.AddRouteFromGFWList("https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt", tunnel); err != nil {
		log.Fatal("添加路由失败 ->", err)
	}

	defer func() {
		_ = proxy.Close()
	}()
	if err := proxy.Listen(context.Background(), "tcp", "127.0.0.1:8580"); err != nil {
		log.Fatal(err)
	}
}
