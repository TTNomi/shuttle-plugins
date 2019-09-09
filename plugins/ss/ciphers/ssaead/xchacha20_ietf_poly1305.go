package ssaead

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	registerAEADCiphers("xchacha20-ietf-poly1305", &xchacha20IetfPoly1305{32, 32, 24, 16})
}

type xchacha20IetfPoly1305 struct {
	keySize   int
	saltSize  int
	nonceSize int
	tagSize   int
}

func (c *xchacha20IetfPoly1305) KeySize() int {
	return c.keySize
}

func (c *xchacha20IetfPoly1305) SaltSize() int {
	return c.saltSize
}

func (c *xchacha20IetfPoly1305) NonceSize() int {
	return c.nonceSize
}

func (c *xchacha20IetfPoly1305) NewEncrypter(key []byte, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	err := HKDF_SHA1(key, salt, []byte("ss-subkey"), subkey)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(subkey)
}

func (c *xchacha20IetfPoly1305) NewDecrypter(key []byte, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	err := HKDF_SHA1(key, salt, []byte("ss-subkey"), subkey)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(subkey)
}
