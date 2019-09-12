package ciphers

import (
	"github.com/pkg/errors"

	"github.com/sipt/shuttle/plugins/ss/ciphers/ssaead"
	"github.com/sipt/shuttle/plugins/ss/ciphers/ssstream"

	connpkg "github.com/sipt/shuttle/conn"
)

type ConnDecorate func(password string, conn connpkg.ICtxConn) (connpkg.ICtxConn, error)

//加密装饰
func CipherDecorate(network, password, method string, conn connpkg.ICtxConn) (connpkg.ICtxConn, error) {
	d := ssstream.GetStreamCiphers(method)
	if d != nil {
		return d(network, password, conn)
	}
	d = ssaead.GetAEADCiphers(method)
	if d != nil {
		return d(network, password, conn)
	}
	return nil, errors.Errorf("[SS Cipher] not support : %s", method)
}
