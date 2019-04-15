package ssproxy

import (
	"io"
	"log"
	"net"
	"sync"
)

const ByteSize = 4108

var pipeBytePool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, ByteSize)
	},
}

type TrafficFunc func(n int)

func Pipe(src, dst io.ReadWriter, trafficFunc TrafficFunc) (written int64, err error) {
	buf := pipeBytePool.Get().([]byte)

	defer func() {
		pipeBytePool.Put(buf)
	}()
	for {
		nr, er := src.Read(buf)

		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				if trafficFunc != nil {
					trafficFunc(nw)
				}
			}
			if ew != nil {
				err = ew
				if oe, ok := ew.(*net.OpError); ok {
					log.Println("write OpError ->", oe.Op, oe.Err)
				}
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
				if oe, ok := err.(*net.OpError); ok {
					log.Println("read OpError ->", oe.Op, oe.Err)
				}
			}
			break
		}
	}

	return written, err
}
