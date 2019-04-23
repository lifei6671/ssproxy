package ssproxy

import (
	"github.com/lifei6671/ssproxy/logs"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

func upgradeType(h http.Header) string {
	for _, v := range h["Connection"] {
		if headerValueContainsToken(v, "Upgrade") {
			return strings.ToLower(h.Get("Upgrade"))
		}
	}
	return ""
}

func headerValueContainsToken(v string, token string) bool {
	v = trimOWS(v)
	if comma := strings.IndexByte(v, ','); comma != -1 {
		return tokenEqual(trimOWS(v[:comma]), token) || headerValueContainsToken(v[comma+1:], token)
	}
	return tokenEqual(v, token)
}

func trimOWS(x string) string {
	// TODO: consider using strings.Trim(x, " \t") instead,
	// if and when it's fast enough. See issue 10292.
	// But this ASCII-only code will probably always beat UTF-8
	// aware code.
	for len(x) > 0 && (x[0] == ' ' || x[0] == '\t') {
		x = x[1:]
	}
	b := x[len(x)-1]

	for len(x) > 0 && (b == ' ' || b == '\t') {
		x = x[:len(x)-1]
	}
	return x
}
func tokenEqual(t1, t2 string) bool {
	if len(t1) != len(t2) {
		return false
	}
	for i, b := range t1 {
		if b >= utf8.RuneSelf {
			// No UTF-8 or non-ASCII allowed in tokens.
			return false
		}
		if lowerASCII(byte(b)) != lowerASCII(t2[i]) {
			return false
		}
	}
	return true
}
func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

// safeClose 安全的关闭
func safeClose(conn io.Closer) {
	defer func() {
		p := recover()
		if p != nil {
			logs.Errorf("panic on closing connection from  %v", p)
		}
	}()
	if conn != nil {
		_ = conn.Close()
	}
}
