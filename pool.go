package ssproxy

import "sync"

var bytesHeaderPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024)
	},
}
