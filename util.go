package ssproxy

import (
	"bufio"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"unicode/utf8"
)

func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}
func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

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
