package ssproxy

//code from https://github.com/shadowsocks/shadowsocks-go/blob/master/shadowsocks/encrypt.go
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"github.com/aead/chacha20"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
	"io"
)

type CryptoStreamer interface {
	EncryptStream(key, iv []byte) (cipher.Stream, error)
	DecryptStream(key, iv []byte) (cipher.Stream, error)
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

type aesStream struct{}

func (s *aesStream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func (s *aesStream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

type aesctrStream struct{}

func (s *aesctrStream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func (s *aesctrStream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

type desStream struct{}

func (s *desStream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}
func (s *desStream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

type blowfishStream struct{}

func (s *blowfishStream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func (s *blowfishStream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

type cast5Stream struct{}

func (s *cast5Stream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func (s *cast5Stream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

type rc4Stream struct{}

func (s *rc4Stream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func (s *rc4Stream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

type chacha20Stream struct{}

func (s *chacha20Stream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

func (s *chacha20Stream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

type chacha20IETFStream struct{}

func (s *chacha20IETFStream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

func (s *chacha20IETFStream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else {
		buf = make([]byte, dataSize)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

type salsaStream struct{}

func (s *salsaStream) EncryptStream(key, iv []byte) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}

func (s *salsaStream) DecryptStream(key, iv []byte) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}

type cipherInfo struct {
	keyLen int
	ivLen  int
	CryptoStreamer
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {16, 16, &aesStream{}},
	"aes-192-cfb":   {24, 16, &aesStream{}},
	"aes-256-cfb":   {32, 16, &aesStream{}},
	"aes-128-ctr":   {16, 16, &aesctrStream{}},
	"aes-192-ctr":   {24, 16, &aesctrStream{}},
	"aes-256-ctr":   {32, 16, &aesctrStream{}},
	"des-cfb":       {8, 8, &desStream{}},
	"bf-cfb":        {16, 8, &blowfishStream{}},
	"cast5-cfb":     {16, 8, &cast5Stream{}},
	"rc4-md5":       {16, 16, &rc4Stream{}},
	"rc4-md5-6":     {16, 6, &rc4Stream{}},
	"chacha20":      {32, 8, &chacha20Stream{}},
	"chacha20-ietf": {32, 12, &chacha20IETFStream{}},
	"salsa20":       {32, 8, &salsaStream{}},
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}
	_, ok := cipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		return nil, ErrEmptyPassword
	}
	mi, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := evpBytesToKey(password, mi.keyLen)

	c = &Cipher{key: key, info: mi}

	if err != nil {
		return nil, err
	}
	return c, nil
}

// Initializes the block cipher with CFB mode, returns IV.
func (c *Cipher) initEncrypt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		c.iv = iv
	} else {
		iv = c.iv
	}
	c.enc, err = c.info.EncryptStream(c.key, iv)
	return
}

func (c *Cipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.DecryptStream(c.key, iv)
	return
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// Copy creates a new cipher at it's initial state.
func (c *Cipher) Copy() *Cipher {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.

	// AES and DES ciphers does not return specific types, so it's difficult
	// to create copy. But their initizliation time is less than 4000ns on my
	// 2.26 GHz Intel Core 2 Duo processor. So no need to worry.

	// Currently, blow-fish and cast5 initialization cost is an order of
	// maganitude slower than other ciphers. (I'm not sure whether this is
	// because the current implementation is not highly optimized, or this is
	// the nature of the algorithm.)

	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}
