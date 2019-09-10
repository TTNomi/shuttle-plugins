package obfs

import (
	"crypto/tls"
	"math/rand"
	"time"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/pkg/pool"
	"golang.org/x/crypto/cryptobyte"
)

const (
	ObfsTLSParamsKeyHost = "obfs-host"
)

func init() {
	rand.Seed(time.Now().Unix())
	Register("tls", NewTLS)
}

// NewTLS
func NewTLS(params map[string]string) (HandleFunc, error) {
	var host string
	if host = params[ObfsTLSParamsKeyHost]; len(host) == 0 {
		return nil, errors.Errorf("[obfs-tls] params [obfs-host] not found")
	}
	return func(sc conn.ICtxConn) (conn.ICtxConn, error) {
		t := &TLS{
			ICtxConn: sc,
			host:     host,
		}
		return t, nil
	}, nil
}

type TLS struct {
	conn.ICtxConn
	host     string
	dataSize int
	flag     byte
}

func (t *TLS) Read(b []byte) (n int, err error) {
	if t.flag&flagFirstRead == 0 {
		t.flag |= flagFirstRead
		// type(1B) + ver(2B) + len(2B) + data(91B)
		// + type(1B) + ver(2B) + len(2B) + data(1B)
		t.dataSize = 102 //B
		for {
			n, err = t.read(b)
			if err != nil {
				return 0, err
			}
			if t.dataSize == 0 {
				break
			}
		}
	}
	return t.read(b)
}

func (t *TLS) read(b []byte) (n int, err error) {
	if t.dataSize > 0 {
		if t.dataSize > len(b) {
			n, err = t.ICtxConn.Read(b)
		} else {
			n, err = t.ICtxConn.Read(b[:t.dataSize])
		}
		t.dataSize -= n
		return
	}
	var offset = 3 // type(1B) + ver(2B) = 3B
	// move offset to length
	_, err = t.ICtxConn.Read(b[:offset])
	if err != nil {
		return 0, err
	}
	// read length
	_, err = t.ICtxConn.Read(b[:2])
	if err != nil {
		return 0, err
	}
	t.dataSize = int(b[0])<<8 | int(b[1])
	if t.dataSize > 0 {
		return t.read(b)
	}
	return 0, nil
}

func (t *TLS) Write(data []byte) (int, error) {
	if t.flag&flagFirstWrite == 0 {
		data, err := makeClientHello(t.host, data)
		if err != nil {
			return 0, err
		}
		_, err = t.ICtxConn.Write(data)
		t.flag = t.flag | flagFirstWrite
		return len(data), err
	}

	b := &cryptobyte.Builder{}
	// Content Type: Application Data
	b.AddUint8(23)
	// Version: TLS 1.2
	b.AddUint16(tls.VersionTLS12)
	// application data
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(data)
	})
	{
		data, err := b.Bytes()
		if err != nil {
			return 0, err
		}
		_, err = t.ICtxConn.Write(data)
		if err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func makeClientHello(serverName string, data []byte) ([]byte, error) {
	const sessionIDLen = 32

	var err error
	b := &cryptobyte.Builder{}
	b.AddUint8(22)                // handshake type
	b.AddUint16(tls.VersionTLS10) // version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1) // client hello type
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(tls.VersionTLS12)          // tls version
			b.AddUint32(uint32(time.Now().Unix())) // timestamp
			buf := pool.GetBuf()
			defer pool.PutBuf(buf)
			_, err = rand.Read(buf[:28]) // make random [32]bytes
			if err != nil {
				err = errors.Errorf("tls: short read from Rand: %s", err.Error())
			}
			b.AddBytes(buf[:28])         // add random [32]byte
			b.AddUint8(sessionIDLen)     // add sessionID.length
			_, err = rand.Read(buf[:32]) // make random [32]bytes
			if err != nil {
				err = errors.Errorf("tls: short read from Rand: %s", err.Error())
			}
			b.AddBytes(buf[:32]) // add SessionID [32]byte

			// cipher suites
			b.AddBytes([]byte{
				// length
				0x00, 0x38,
				// cipher suites
				0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
				0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
				0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
				0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
			})

			// compression
			b.AddUint8(1) // length
			b.AddUint8(0) // method: null

			// Extension
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				// Extension: sessionTicket tls
				b.AddUint16(35)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(data)
				})
				// Extension: server_name
				b.AddUint16(0)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0) // name_type = host_name
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(serverName))
						})
					})
				})
				// Extension: ec_point_formats
				b.AddUint16(11) // type
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{0x01, 0x00, 0x02})
					})
				})
				// Extension: supported_groups
				b.AddUint16(10)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{
							0x00, 0x1d, // x25519
							0x00, 0x17, // secp256r1
							0x00, 0x19, // secp521r1
							0x00, 0x18, // secp384r1
						})
					})
				})
				// Extension: signature_algorithms
				b.AddUint16(13)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{
							0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
							0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03})
					})
				})
				// Extension: encrypt_then_mac
				b.AddBytes([]byte{
					0x00, 0x16, // type
					0x00, 0x00, // length
				})
				// Extension: extended_master_secret
				b.AddBytes([]byte{
					0x00, 0x17, // type
					0x00, 0x00, // length
				})
			})
			return
		})
	})
	if err != nil {
		return nil, errors.Errorf("tls: short read from Rand: %s", err.Error())
	}
	return b.Bytes()
}
