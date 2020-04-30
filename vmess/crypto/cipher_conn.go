package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/sipt/shuttle/pkg/pool"
)

//var aeadCiphers = make(map[string]IAEADCipher)
//
//func registerAEADCiphers(method string, c IAEADCipher) {
//	aeadCiphers[method] = c
//}

func GetAEADCiphers(method string) func([]byte, []byte, net.Conn) (net.Conn, error) {
	return func(key []byte, wNonce []byte, conn net.Conn) (net.Conn, error) {
		var (
			err error
			c   cipher.AEAD
		)
		switch method {
		case "aes-128-gcm":
			c, err = NewAesGcm(key)
		case "chacha20-poly1305":
			c, err = NewChacha20(key)
		default:
			return nil, fmt.Errorf("not support: %s", method)
		}
		if err != nil {
			return nil, err
		}

		//if network == "tcp" {
		return &aeadConn{
			Conn:        conn,
			AEAD:        c,
			wNonce:      wNonce,
			rNonce:      make([]byte, c.NonceSize()),
			readBuffer:  bytes.NewBuffer(pool.GetBuf()[:0]),
			writeBuffer: bytes.NewBuffer(pool.GetBuf()[:0]),
		}, nil
		//} else {
		//return &aeadPocketConn{
		//	ICtxConn:    conn,
		//	IAEADCipher: c,
		//	key:         evpBytesToKey(password, c.KeySize()),
		//	wNonce:      make([]byte, c.NonceSize()),
		//	rNonce:      make([]byte, c.NonceSize()),
		//	readBuffer:  bytes.NewBuffer(pool.GetBuf()[:0]),
		//	writeBuffer: bytes.NewBuffer(pool.GetBuf()[:0]),
		//}, nil
		//}
	}
}

type aeadConn struct {
	net.Conn
	cipher.AEAD
	rNonce      []byte
	wCount      uint16
	wNonce      []byte
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
}

func (a *aeadConn) PrepareWrite(b []byte) (n int, err error) {
	return a.writeBuffer.Write(b)
}

func (a *aeadConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (a *aeadConn) Write(b []byte) (n int, err error) {
	n = len(b)
	payloadSize := pool.BufferSize - a.Overhead() - 2
	rawBytes := pool.GetBuf()
	defer pool.PutBuf(rawBytes)
	nBytes := 0
	for {
		b, nBytes = splitBytes(b, rawBytes)

		binary.BigEndian.PutUint16(rawBytes[:2], uint16(nBytes+a.Overhead()))
		binary.BigEndian.PutUint16(a.wNonce[:2], a.wCount)

		a.Seal(rawBytes[:0], a.wNonce[:a.NonceSize()], rawBytes[:payloadSize], nil)
		a.wCount++
		_, err = a.Conn.Write(rawBytes[:2+nBytes+a.Overhead()])
		if err != nil {
			return 0, err
		}
		if len(b) == 0 {
			break
		}
	}
	return
}
func splitBytes(src, dst []byte) ([]byte, int) {
	if len(dst) > len(src) {
		copy(dst, src)
		return src[len(src):], len(src)
	}
	copy(dst, src)
	return src[len(dst):], len(dst)
}
