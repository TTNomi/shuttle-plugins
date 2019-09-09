package ssstream

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"

	"github.com/sipt/shuttle/pkg/pool"
	"github.com/sirupsen/logrus"

	connpkg "github.com/sipt/shuttle/conn"
)

var streamCiphers = make(map[string]IStreamCipher)

func registerStreamCiphers(method string, c IStreamCipher) {
	streamCiphers[method] = c
}

func GetStreamCiphers(method string) func(string, connpkg.ICtxConn) (connpkg.ICtxConn, error) {
	c, ok := streamCiphers[method]
	if !ok {
		return nil
	}
	return func(password string, conn connpkg.ICtxConn) (connpkg.ICtxConn, error) {
		iv := make([]byte, c.IVLen())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		sc := &streamConn{
			ICtxConn:      conn,
			IStreamCipher: c,
			key:           evpBytesToKey(password, c.KeyLen()),
		}
		var err error
		sc.Encrypter, err = sc.NewEncrypter(sc.key, iv)
		_, err = conn.Write(iv)
		return sc, err
	}
}

type IStreamCipher interface {
	KeyLen() int
	IVLen() int
	NewEncrypter(key []byte, iv []byte) (cipher.Stream, error)
	NewDecrypter(key []byte, iv []byte) (cipher.Stream, error)
}

type streamConn struct {
	connpkg.ICtxConn
	IStreamCipher
	key       []byte
	Encrypter cipher.Stream
	Decrypter cipher.Stream
}

func (s *streamConn) Read(b []byte) (n int, err error) {
	if s.Decrypter == nil {
		iv := make([]byte, s.IVLen())
		if _, err = s.ICtxConn.Read(iv); err != nil {
			return
		}
		s.Decrypter, err = s.NewDecrypter(s.key, iv)
		if err != nil {
			logrus.Errorf("[Stream ICtxConn] init decrypter failed: %v", err)
			return 0, err
		}
	}
	buf := pool.GetBuf()
	if len(buf) < len(b) {
		pool.PutBuf(buf)
		buf = make([]byte, len(b))
	}
	defer pool.PutBuf(buf)
	buf = buf[:len(b)]
	n, err = s.ICtxConn.Read(buf)
	if err != nil {
		return
	}
	s.Decrypter.XORKeyStream(b[:n], buf[:n])
	return
}

func (s *streamConn) Write(b []byte) (n int, err error) {
	buf := pool.GetBuf()
	if len(buf) < len(b) {
		pool.PutBuf(buf)
		buf = make([]byte, len(b))
	} else {
		buf = buf[:len(b)]
		defer pool.PutBuf(buf)
	}
	s.Encrypter.XORKeyStream(buf, b)
	return s.ICtxConn.Write(buf)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, MD5([]byte(password)))
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], MD5(d))
	}
	return m[:keyLen]
}

func MD5(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}
