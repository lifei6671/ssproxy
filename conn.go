package ssproxy

import (
	"context"
	"golang.org/x/time/rate"
	"net"
	"time"
)

const BurstLimit = 1000 * 1000 * 1000

type SocksConn struct {
	net.Conn
	limiter *rate.Limiter
}

func NewProxyConn(conn net.Conn) *SocksConn {
	return &SocksConn{Conn: conn}
}

// SetRateLimit 设置网速
func (c *SocksConn) SetRateLimit(bytesPerSec float64) {
	c.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), BurstLimit)
	c.limiter.AllowN(time.Now(), BurstLimit) // spend initial burst
}

func (c *SocksConn) Write(p []byte) (int, error) {
	if c.limiter == nil {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p)
	if err != nil {
		return n, err
	}
	if err := c.limiter.WaitN(context.Background(), n); err != nil {
		return n, err
	}
	return n, err
}

type SocksProxyTCPConn struct {
	SocksConn
}

type SocksProxyUDPConn struct {
	SocksConn
}
