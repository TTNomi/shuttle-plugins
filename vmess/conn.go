package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"

	"github.com/sipt/shuttle/plugins/vmess/crypto"
)

const (
	Version = byte(1)
)

// NewClientSession creates a new ClientSession.
func NewConn(wc net.Conn, dest *Destination, account *Account) (*Conn, error) {
	randomBytes := make([]byte, 33) // 16 + 16 + 1
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		plain:   wc,
		dest:    dest,
		account: account,
	}
	copy(conn.requestBodyKey[:], randomBytes[:16])
	copy(conn.requestBodyIV[:], randomBytes[16:32])
	conn.responseHeader = randomBytes[32]
	conn.responseBodyKey = md5.Sum(conn.requestBodyKey[:])
	conn.responseBodyIV = md5.Sum(conn.requestBodyIV[:])
	conn.idHash = DefaultIDHash
	switch account.Security {
	case SecurityType_AUTO, SecurityType_AES128_GCM:
		conn.Conn, err = crypto.GetAEADCiphers("aes-128-gcm")(conn.requestBodyIV[:], conn.responseBodyIV[:], wc)
	case SecurityType_CHACHA20_POLY1305:
	}
	return conn, err
}

type Conn struct {
	net.Conn
	plain           net.Conn
	dest            *Destination
	idHash          IDHash
	requestBodyKey  [16]byte
	requestBodyIV   [16]byte
	responseBodyKey [16]byte
	responseBodyIV  [16]byte
	responseHeader  byte
	account         *Account
}

func (c *Conn) sendRequestHeader() error {
	timestamp := GenerateTimestamp()
	h := c.idHash(c.account.AnyValidID().Bytes())
	err := binary.Write(h, binary.BigEndian, uint64(timestamp))
	if err != nil {
		return err
	}
	_, err = c.Write(h.Sum(nil))
	if err != nil {
		return err
	}

	buffer := &bytes.Buffer{}
	buffer.WriteByte(Version)
	buffer.Write(c.requestBodyIV[:])
	buffer.Write(c.requestBodyKey[:])
	buffer.WriteByte(c.responseHeader)
	buffer.WriteByte(RequestOptionChunkStream)

	paddingLen := Roll(16)
	buffer.WriteByte(byte(paddingLen<<4) | byte(c.account.Security))
	buffer.WriteByte(0)
	if c.dest.Network == Network_TCP {
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

	iv := hashTimestamp(timestamp)
	aesBlock, err := aes.NewCipher(c.account.ID.CmdKey())
	if err != nil {
		return err
	}
	fmt.Println(string(buffer.Bytes()))
	fmt.Println(buffer.Bytes())
	aesStream := cipher.NewCFBEncrypter(aesBlock, iv[:])
	aesStream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
	_, err = c.plain.Write(buffer.Bytes())
	return err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
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
