package vmess

import (
	"github.com/golang/protobuf/proto"
)

type Network int32

const (
	Network_Unknown Network = 0
	Network_TCP     Network = 1
	Network_UDP     Network = 2

	RequestCommandTCP = byte(0x01)
	RequestCommandUDP = byte(0x02)
	RequestCommandMux = byte(0x03)
)

func (n Network) SystemString() string {
	switch n {
	case Network_TCP:
		return "tcp"
	case Network_UDP:
		return "udp"
	default:
		return "unknown"
	}
}

const (
	// RequestOptionChunkStream indicates request payload is chunked. Each chunk consists of length, authentication and payload.
	RequestOptionChunkStream byte = 0x01
	// RequestOptionConnectionReuse indicates client side expects to reuse the connection.
	RequestOptionConnectionReuse byte = 0x02
	RequestOptionChunkMasking    byte = 0x04
	RequestOptionGlobalPadding   byte = 0x08
)

type SecurityType int32

const (
	SecurityType_UNKNOWN           SecurityType = 0
	SecurityType_LEGACY            SecurityType = 1
	SecurityType_AUTO              SecurityType = 2
	SecurityType_AES128_GCM        SecurityType = 3
	SecurityType_CHACHA20_POLY1305 SecurityType = 4
	SecurityType_NONE              SecurityType = 5
)

var SecurityType_name = map[int32]string{
	0: "unknown",
	1: "legacy",
	2: "auto",
	3: "aes128_gcm",
	4: "chacha20_poly1305",
	5: "none",
}

var SecurityType_value = map[string]int32{
	"unknown":           0,
	"legacy":            1,
	"auto":              2,
	"aes128_gcm":        3,
	"chacha20_poly1305": 4,
	"none":              5,
}

func (x SecurityType) String() string {
	return proto.EnumName(SecurityType_name, int32(x))
}

func SecurityTypeMapping(cipher string) SecurityType {
	return SecurityType(SecurityType_value[cipher])
}
