package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"

	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/plugins/vmess/crypto"
)

const (
	Version = byte(1)
)

// NewClientSession creates a new ClientSession.
func NewConn(wc conn.ICtxConn, dest *Destination, account *Account) (conn.ICtxConn, error) {
	randomBytes := make([]byte, 33) // 16 + 16 + 1
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		plain:      wc,
		dest:       dest,
		account:    account,
		firstRead:  true,
		firstWrite: true,
	}
	copy(conn.requestBodyKey[:], randomBytes[:16])
	copy(conn.requestBodyIV[:], randomBytes[16:32])
	conn.responseHeader = randomBytes[32]
	conn.idHash = DefaultIDHash
	conn.responseBodyKey = md5.Sum(conn.requestBodyKey[:])
	conn.responseBodyIV = md5.Sum(conn.requestBodyIV[:])
	conn.ICtxConn, err = crypto.GetAEADCiphers(account.Security)(
		clone(conn.requestBodyKey[:]), clone(conn.responseBodyKey[:]), clone(conn.requestBodyIV[:]), clone(conn.responseBodyIV[:]), wc)
	return conn, err
}

func clone(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

const (
	RequestCommandTCP = byte(0x01)
	RequestCommandUDP = byte(0x02)
)

type Conn struct {
	conn.ICtxConn
	plain           net.Conn
	dest            *Destination
	idHash          IDHash
	requestBodyKey  [16]byte
	requestBodyIV   [16]byte
	responseBodyKey [16]byte
	responseBodyIV  [16]byte
	responseHeader  byte
	account         *Account
	firstRead       bool
	firstWrite      bool
}

func (c *Conn) sendRequestHeader() error {
	timestamp := GenerateTimestamp()
	h := c.idHash(c.account.AnyValidID().Bytes())
	err := binary.Write(h, binary.BigEndian, uint64(timestamp))
	if err != nil {
		return err
	}
	_, err = c.plain.Write(h.Sum(nil))
	if err != nil {
		return err
	}

	buffer := &bytes.Buffer{}
	buffer.WriteByte(Version)
	buffer.Write(c.requestBodyIV[:])
	buffer.Write(c.requestBodyKey[:])
	buffer.WriteByte(c.responseHeader)
	buffer.WriteByte(0x01)

	paddingLen := Roll(16)
	buffer.WriteByte(byte(paddingLen<<4) | byte(c.account.Security))
	buffer.WriteByte(0)
	if c.dest.Network == "tcp" {
		buffer.WriteByte(RequestCommandTCP)
	} else {
		buffer.WriteByte(RequestCommandUDP)
	}
	// Port
	_ = binary.Write(buffer, binary.BigEndian, c.dest.Port.Value())
	// Address Type
	// 0x01: IPV4
	// 0x02: Domain
	// 0x03: IPV6
	buffer.WriteByte(byte(c.dest.Address.Family()))
	if c.dest.Address.Family().IsDomain() {
		domain := c.dest.Address.Domain()
		// len(domain)
		buffer.WriteByte(byte(len(domain)))
		// domain
		buffer.Write([]byte(domain))
	} else {
		// ip
		buffer.Write(c.dest.Address.IP())
	}

	// padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		_, _ = rand.Read(padding)
		buffer.Write(padding)
	}

	// FNV1a hash
	{
		fnv1a := fnv.New32a()
		_, _ = fnv1a.Write(buffer.Bytes())
		buffer.Write(fnv1a.Sum(nil))
	}

	logrus.WithField("send_header", string(buffer.Bytes())).Debug("[vmess] send header")
	iv := hashTimestamp(timestamp)
	aesBlock, err := aes.NewCipher(c.account.ID.CmdKey())
	if err != nil {
		return err
	}
	aesStream := cipher.NewCFBEncrypter(aesBlock, iv[:])
	aesStream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
	_, err = c.plain.Write(buffer.Bytes())
	return err
}

func (c *Conn) receiveResponseHeader() error {
	aesBlock, err := aes.NewCipher(c.responseBodyKey[:])
	if err != nil {
		return err
	}

	aseStream := cipher.NewCFBDecrypter(aesBlock, c.responseBodyIV[:])
	buf := make([]byte, 4)
	_, err = io.ReadFull(c.plain, buf)
	if err != nil {
		return err
	}
	aseStream.XORKeyStream(buf, buf[:4])

	switch {
	case buf[0] != c.responseHeader:
		return errors.New("invalid response header")
	case buf[2] != 0:
		return errors.New("not support [Dynamic-Port]")
	default:
		break
	}
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.firstRead {
		c.firstRead = false
		err = c.receiveResponseHeader()
		if err != nil {
			return 0, err
		}
	}
	return c.ICtxConn.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.firstWrite {
		c.firstWrite = false
		err = c.sendRequestHeader()
		if err != nil {
			return 0, err
		}
	}
	return c.ICtxConn.Write(b)
}

func hashTimestamp(t int64) []byte {
	var (
		b [8]byte
		h = md5.New()
	)
	binary.BigEndian.PutUint64(b[:], uint64(t))
	for i := 0; i < 4; i++ {
		h.Write(b[:])
	}
	return h.Sum(nil)
}
