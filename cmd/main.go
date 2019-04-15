package main

import (
	"github.com/lifei6671/ssproxy"
	"log"
	"net"
)

func main() {
	go func() {

		proxy := ssproxy.NewHttpProxy()

		if err := proxy.Listen("tcp", ":8581"); err != nil {
			log.Println(err)
		}

	}()
	l, err := net.Listen("tcp", ":8580")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := l.Accept()

		if err != nil {
			log.Println(err)
			continue
		}
		go func() {
			socksConn := ssproxy.NewSocks5Conn(conn, ssproxy.AuthMethodNotRequired)
			defer socksConn.Close()

			if err := socksConn.Handshake(); err != nil {
				log.Println("握手失败", err)
				return
			}

			if err := socksConn.Forward(); err != nil {
				log.Println(err)
			}
		}()
	}
}
