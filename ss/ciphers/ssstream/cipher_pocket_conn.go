package ssstream

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/pkg/pool"
	"github.com/sirupsen/logrus"

	connpkg "github.com/sipt/shuttle/conn"
)

const maxPacketSize = 64 * 1024

type streamPocketConn struct {
	connpkg.ICtxConn
	IStreamCipher
	key         []byte
	Encrypter   cipher.Stream
	Decrypter   cipher.Stream
	writeBuffer *bytes.Buffer
	readBuffer  *bytes.Buffer
	remoteAddr  []byte
}

func (s *streamPocketConn) Read(b []byte) (n int, err error) {
	if s.Decrypter != nil {
		return s.readBuffer.Read(b)
	}
	buf := make([]byte, maxPacketSize)
	if n, err = s.ICtxConn.Read(buf); err != nil {
		return
	}
	buf = buf[:n]
	if s.Decrypter == nil {
		iv := buf[:s.IVLen()]
		buf = buf[s.IVLen():]
		s.Decrypter, err = s.NewDecrypter(s.key, iv)
		if err != nil {
			logrus.Errorf("[Stream ICtxConn] init decrypter failed: %v", err)
			return 0, err
		}
	}
	s.Decrypter.XORKeyStream(buf, buf)
	_, err = s.readBuffer.Write(buf[len(s.remoteAddr):])
	if err != nil {
		return 0, err
	}
	return s.readBuffer.Read(b)
}

func (s *streamPocketConn) Write(b []byte) (n int, err error) {
	if s.Encrypter == nil {
		var err error
		iv := make([]byte, s.IVLen())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return 0, errors.Errorf("[ss] init iv failed: %s", err.Error())
		}
		if s.Encrypter, err = s.NewEncrypter(s.key, iv); err != nil {
			return 0, errors.Errorf("[ss] init encrypter failed: %s", err.Error())
		}
		_, err = s.writeBuffer.Write(iv)
		if err != nil {
			return 0, errors.Errorf("[ss] send salt failed: %s", err.Error())
		}
		s.writeBuffer.Write(b)
		s.remoteAddr = b
		return len(b), nil
	}
	s.writeBuffer.Write(b)
	buf := pool.GetBuf()
	if len(buf) < s.writeBuffer.Len() {
		pool.PutBuf(buf)
		buf = make([]byte, len(b)+s.IVLen())
	} else {
		buf = buf[:s.writeBuffer.Len()]
		defer pool.PutBuf(buf)
	}
	_, err = s.writeBuffer.Read(buf[:s.IVLen()])
	if err != nil {
		return 0, err
	}
	s.Encrypter.XORKeyStream(buf[s.IVLen():], s.writeBuffer.Bytes())
	return s.ICtxConn.Write(buf)
}
