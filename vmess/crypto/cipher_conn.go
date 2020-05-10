package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/sipt/shuttle/plugins/vmess/common"

	"github.com/sipt/shuttle/conn"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/pkg/pool"
)

//var aeadCiphers = make(map[string]IAEADCipher)
//
//func registerAEADCiphers(method string, c IAEADCipher) {
//	aeadCiphers[method] = c
//}

func GetAEADCiphers(method common.SecurityType) func(reqKey, respKey, reqIV, respIV []byte, conn conn.ICtxConn) (conn.ICtxConn, error) {
	return func(reqKey, respKey, reqIV, respIV []byte, conn conn.ICtxConn) (conn.ICtxConn, error) {
		var (
			err error
			c   = &aeadConn{
				ICtxConn:    conn,
				readBuffer:  bytes.NewBuffer(pool.GetBuf()[:0]),
				writeBuffer: bytes.NewBuffer(pool.GetBuf()[:0]),
				wCipher: &aeadCipher{
					iv: reqIV,
				},
				rCipher: &aeadCipher{
					iv: respIV,
				},
			}
		)

		switch method {
		case common.SecurityType_AES128_GCM:
			c.wCipher.AEAD, err = NewAesGcm(reqKey)
			if err != nil {
				return nil, err
			}
			c.rCipher.AEAD, err = NewAesGcm(respKey)
			if err != nil {
				return nil, err
			}
		case common.SecurityType_CHACHA20_POLY1305:
			c.wCipher.AEAD, err = NewChacha20(makeKey(reqKey))
			if err != nil {
				return nil, err
			}
			c.rCipher.AEAD, err = NewChacha20(makeKey(respKey))
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("not support: %s", method)
		}
		if err != nil {
			return nil, err
		}

		//if network == "tcp" {
		return c, nil
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

func makeKey(in []byte) []byte {
	reply := make([]byte, 32)
	key := md5.Sum(in)
	copy(reply, key[:])
	key = md5.Sum(key[:])
	copy(reply[16:], key[:])
	return reply
}

type aeadCipher struct {
	cipher.AEAD
	count uint16
	iv    []byte
}

func (a *aeadCipher) Seal(dst, plaintext, additionalData []byte) []byte {
	binary.BigEndian.PutUint16(a.iv[:2], a.count)
	reply := a.AEAD.Seal(dst, a.iv[:a.NonceSize()], plaintext, additionalData)
	a.count++
	return reply
}

func (a *aeadCipher) Open(dst, ciphertext, additionalData []byte) ([]byte, error) {
	binary.BigEndian.PutUint16(a.iv[:2], a.count)
	reply, err := a.AEAD.Open(dst, a.iv[:a.NonceSize()], ciphertext, additionalData)
	a.count++
	return reply, err
}

type aeadConn struct {
	conn.ICtxConn
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	wCipher     *aeadCipher
	rCipher     *aeadCipher
}

func (a *aeadConn) PrepareWrite(b []byte) (n int, err error) {
	return a.writeBuffer.Write(b)
}

func (a *aeadConn) Read(b []byte) (n int, err error) {
	if a.readBuffer.Len() > 0 {
		return a.readBuffer.Read(b)
	}

	buf := pool.GetBuf()
	defer pool.PutBuf(buf)

	n, err = a.ICtxConn.Read(buf)
	if err != nil {
		return 0, errors.Wrap(err, "read payload_size failed")
	}

	payloadSize := int(binary.BigEndian.Uint16(buf[:2]))
	if n > 2 {
		a.readBuffer.Write(buf[2:n])
		payloadSize -= n - 2
	}
	for payloadSize > 0 {
		chunkSize := payloadSize
		if chunkSize > pool.BufferSize {
			chunkSize = pool.BufferSize
		}

		n, err = a.ICtxConn.Read(buf[:chunkSize])
		if err != nil {
			return 0, errors.Wrap(err, "read payload failed")
		}
		_, err = a.readBuffer.Write(buf[:n])
		if err != nil {
			return 0, errors.Wrap(err, "read payload failed")
		}
		payloadSize -= n
	}

	payload := a.readBuffer.Bytes()
	payload, err = a.rCipher.Open(payload[:0], payload, nil)
	if err != nil {
		return 0, err
	}
	a.readBuffer.Reset()
	_, err = a.readBuffer.Write(payload)
	if err != nil {
		return 0, errors.Wrap(err, "write data to buffer failed")
	}
	return a.readBuffer.Read(b)
}

func (a *aeadConn) Write(b []byte) (n int, err error) {
	n = len(b)
	//payloadSize := pool.BufferSize - a.Overhead()
	rawBytes := pool.GetBuf()
	defer pool.PutBuf(rawBytes)
	chunkSize := 0
	for {
		payloadBytes := rawBytes[2:pool.BufferSize]
		b, chunkSize = splitBytes(b, payloadBytes)
		payloadBytes = payloadBytes[:chunkSize+a.wCipher.Overhead()]
		binary.BigEndian.PutUint16(rawBytes[:2], uint16(chunkSize+a.wCipher.Overhead()))

		a.wCipher.Seal(payloadBytes[:0], payloadBytes[:chunkSize], nil)
		_, err = a.ICtxConn.Write(rawBytes[:2+chunkSize+a.wCipher.Overhead()])
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
