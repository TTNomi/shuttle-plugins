package common

type SecurityType int32

const (
	SecurityType_AUTO              SecurityType = 2
	SecurityType_AES128_GCM        SecurityType = 3
	SecurityType_CHACHA20_POLY1305 SecurityType = 4
)

var SecurityType_name = map[SecurityType]string{
	2: "auto",
	3: "aes128_gcm",
	4: "chacha20_poly1305",
}

var SecurityType_value = map[string]SecurityType{
	"auto":              2,
	"aes128_gcm":        3,
	"chacha20_poly1305": 4,
}
