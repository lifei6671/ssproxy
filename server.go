package ssproxy

type ProxyServer struct {
	socksVersion []SocksVersion
	log          Logger
	cancel       func()
}
