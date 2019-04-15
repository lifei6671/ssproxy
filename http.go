package ssproxy

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type HttpProxy struct {
	proxy   *httputil.ReverseProxy
	byteSec float64
}

func NewHttpProxy() *HttpProxy {
	return &HttpProxy{
		proxy: &httputil.ReverseProxy{
			Director: director,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.DialTimeout(network, addr, time.Second*30)
				},
			},
		},
	}
}

func (h *HttpProxy) Listen(network, address string) error {
	l, err := net.Listen(network, address)
	if err != nil {
		ErrorLogger.Println("监听 HTTP 代理端口失败 ->", err)
		return err
	}
	GeneralLogger.Println("HTTP Proxy 正在监听 ->", l.Addr())
	if err := http.Serve(l, h); err != nil {
		ErrorLogger.Println("启动 HTTP 代理服务器失败->", err)
		return err
	}
	return nil
}

func director(request *http.Request) {
	u, err := url.Parse(request.RequestURI)
	if err != nil {
		return
	}
	request.RequestURI = u.RequestURI()
	v := request.Header.Get("Proxy-Connection")
	if v != "" {
		request.Header.Del("Proxy-Connection")
		request.Header.Del("Connection")
		request.Header.Add("Connection", v)
	}
}

func (h *HttpProxy) Forward(response http.ResponseWriter, request *http.Request) {
	var conn net.Conn
	if hj, ok := response.(http.Hijacker); ok {
		var err error
		if conn, _, err = hj.Hijack(); err != nil {
			http.Error(response, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(response, "Hijacker failed", http.StatusInternalServerError)
		return
	}
	localConn := NewHttpProxyConn(conn)
	if h.byteSec > 0 {
		localConn.SetRateLimit(h.byteSec)
	}
	defer func() {
		if err := localConn.Close(); err != nil {
			ErrorLogger.Println("关闭连接出错 ->", err)
		}
	}()

	remoteConn, err := net.Dial("tcp", request.Host)
	if err != nil {
		if _, err := fmt.Fprintf(localConn, "HTTP/1.0 500 NewRemoteSocks failed, err:%s\r\n\r\n", err); err != nil {
			ErrorLogger.Println("响应客户端失败 ->", err)
		}
		return
	}

	if request.Body != nil {
		if _, err = io.Copy(remoteConn, request.Body); err != nil {
			ErrorLogger.Println("向目标服务器写入数据失败 ->", remoteConn.RemoteAddr(), err)
			if _, err := fmt.Fprintf(localConn, "%d %s", http.StatusBadGateway, err.Error()); err != nil {
				ErrorLogger.Println("响应客户端失败 ->", err)
			}
			return
		}
	}
	if _, err := fmt.Fprintf(localConn, "HTTP/1.0 200 Connection established\r\n\r\n"); err != nil {
		ErrorLogger.Println("响应客户端失败 ->", err)
		return
	}

	GeneralLogger.Printf("开始转换数据 -> %s ---> %s", conn.RemoteAddr(), remoteConn.RemoteAddr())

	go func() {
		if _, err := Pipe(remoteConn, localConn, nil); err != nil {
			ErrorLogger.Println("数据转换时出错 ->", err)
		}
	}()
	if _, err := Pipe(localConn, remoteConn, nil); err != nil {
		ErrorLogger.Println("数据转换时出错 ->", err)
	}
}

// ServeHTTP implements HTTP Handler
func (h *HttpProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	GeneralLogger.Printf("接受到新请求 -> %s - %s - %s", request.Method, request.RemoteAddr, request.Host)
	if request.Method == "CONNECT" {
		h.Forward(response, request)
	} else {
		h.proxy.ServeHTTP(response, request)
	}
}

func (h *HttpProxy) SetRateLimit(bytesPerSec float64) {
	h.byteSec = bytesPerSec
}

type HttpProxyConn struct {
	limiter *rate.Limiter
	net.Conn
}

func NewHttpProxyConn(conn net.Conn) *HttpProxyConn {
	return &HttpProxyConn{Conn: conn}
}

// SetRateLimit 设置网速
func (conn *HttpProxyConn) SetRateLimit(bytesPerSec float64) {
	conn.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), BurstLimit)
	conn.limiter.AllowN(time.Now(), BurstLimit) // spend initial burst
}

func (conn *HttpProxyConn) Write(p []byte) (int, error) {
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
