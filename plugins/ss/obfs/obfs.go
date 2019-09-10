package obfs

import (
	"fmt"

	"github.com/sipt/shuttle/conn"
)

const (
	DefaultObfsHost = "www.bing.com"
)

type HandleFunc func(conn.ICtxConn) (conn.ICtxConn, error)
type NewFunc func(map[string]string) (HandleFunc, error)

var creator = make(map[string]NewFunc)

// Register: register {key: marshal}
func Register(key string, f NewFunc) {
	creator[key] = f
}

// GetMarshal: get Obfs by key
func Get(key string, params map[string]string) (HandleFunc, error) {
	f, ok := creator[key]
	if !ok {
		return nil, fmt.Errorf("obfs not support: %s", key)
	}
	return f(params)
}
