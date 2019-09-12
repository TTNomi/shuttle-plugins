package ssaead

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	connpkg "github.com/sipt/shuttle/conn"
)

const maxPacketSize = 64 * 1024

type aeadPocketConn struct {
	connpkg.ICtxConn
	IAEADCipher
	key         []byte
	rNonce      []byte
	wNonce      []byte
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	Encrypter   cipher.AEAD
	Decrypter   cipher.AEAD
	remoteAddr  []byte
}

func (a *aeadPocketConn) Read(b []byte) (n int, err error) {
	if a.Decrypter != nil {
		return a.readBuffer.Read(b)
	}
	buf := make([]byte, maxPacketSize)
	if n, err = a.ICtxConn.Read(buf); err != nil {
		return
	}
	buf = buf[:n]
	if a.Decrypter == nil {
		salt := buf[:a.SaltSize()]
		buf = buf[a.SaltSize():]
		a.Decrypter, err = a.NewDecrypter(a.key, salt)
		if err != nil {
			logrus.Errorf("[AEAD ICtxConn] init decrypter failed: %v", err)
			return 0, err
		}
	}
	buf, err = a.Decrypter.Open(buf[0:0], a.rNonce, buf, nil)
	if err != nil {
		return 0, err
	}
	_, err = a.readBuffer.Write(buf[len(a.remoteAddr):])
	if err != nil {
		return 0, err
	}
	return a.readBuffer.Read(b)
}

func (a *aeadPocketConn) Write(b []byte) (n int, err error) {
	if a.Encrypter == nil {
		salt := make([]byte, a.SaltSize())
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return 0, errors.Errorf("[ss] init salt failed: %s", err.Error())
		}
		if a.Encrypter, err = a.NewEncrypter(a.key, salt); err != nil {
			return 0, errors.Errorf("[ss] init encrypter failed: %s", err.Error())
		}
		_, err = a.writeBuffer.Write(salt)
		if err != nil {
			return 0, errors.Errorf("[ss] send salt failed: %s", err.Error())
		}
		a.writeBuffer.Write(b)
		a.remoteAddr = b
		return len(b), nil
	}
	a.writeBuffer.Write(b)
	buf := make([]byte, a.writeBuffer.Len()+a.Encrypter.Overhead())
	_, err = a.writeBuffer.Read(buf[:a.SaltSize()])
	if err != nil {
		return
	}
	fmt.Println(a.writeBuffer.Bytes())
	a.Encrypter.Seal(buf[a.SaltSize():a.SaltSize()], a.wNonce, a.writeBuffer.Bytes(), nil)
	_, err = a.ICtxConn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
