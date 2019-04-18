package ssproxy

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const ByteSize = 4108

var pipeBytePool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, ByteSize)
	},
}

type TrafficFunc func(n int)

type Pipeline struct {
	read  time.Duration
	write time.Duration
}

func NewPipeline(readDeadline time.Duration, writeDeadline time.Duration) *Pipeline {
	return &Pipeline{read: readDeadline, write: writeDeadline}
}

func (p *Pipeline) Pipe(local, remote net.Conn, trafficFunc TrafficFunc) (written int64, err error) {
	buf := pipeBytePool.Get().([]byte)

	defer func() {
		pipeBytePool.Put(buf)
	}()
	for {
		if p.read > 0 {
			_ = local.SetReadDeadline(time.Now().Add(p.read))
		}
		nr, er := local.Read(buf)

		if nr > 0 {
			if p.write > 0 {
				_ = remote.SetWriteDeadline(time.Now().Add(p.write))
			}
			nw, ew := remote.Write(buf[0:nr])
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
func Pipe(reader io.Reader, writer io.Writer, trafficFunc TrafficFunc) (written int64, err error) {
	buf := pipeBytePool.Get().([]byte)

	defer func() {
		pipeBytePool.Put(buf)
	}()
	for {

		nr, er := reader.Read(buf)

		if nr > 0 {
			nw, ew := writer.Write(buf[0:nr])
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
