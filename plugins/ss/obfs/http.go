package obfs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/pkg/pool"
)

const (
	reqTemplete = "%s http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.%d.%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nContent-Length: %d\r\n\r\n"

	flagFirstWrite = 1
	flagFirstRead  = 1 << 1

	ObfsHTTPParamsKeyHost   = "http-host"
	ObfsHTTPParamsKeyMethod = "http-method"
)

func init() {
	Register("http", NewHTTP)
}

// NewHTTP
func NewHTTP(params map[string]string) (HandleFunc, error) {
	var host, method string
	if host = params[ObfsHTTPParamsKeyHost]; len(host) == 0 {
		return nil, errors.Errorf("[obfs-http] params [host] not found")
	}
	if method = params[ObfsHTTPParamsKeyMethod]; len(method) == 0 {
		method = http.MethodGet
	}
	return func(sc conn.ICtxConn) (conn.ICtxConn, error) {
		return &HTTP{
			ICtxConn: sc,
			host:     host,
			method:   method,
		}, nil
	}, nil
}

type HTTP struct {
	conn.ICtxConn
	forgc  []byte
	buf    []byte
	host   string
	method string
	flag   byte
}

func (h *HTTP) Read(b []byte) (int, error) {
	if h.flag&flagFirstRead == 0 {
		h.buf = pool.GetBuf()
		h.forgc = h.buf
		var (
			err   error
			state byte
		)
		n, err := h.ICtxConn.Read(h.buf)
		if err != nil {
			return 0, err
		}
		h.flag |= flagFirstRead
		for i, c := range h.buf[:n] {
			switch c {
			case '\r':
				if state&1 == 0 {
					state += 1
				} else {
					state = 0
				}
			case '\n':
				if state&1 == 1 {
					state += 1
				} else {
					state = 0
				}
			default:
				state = 0
			}
			if state == 4 {
				h.buf = h.buf[i+1 : n]
				break
			}
		}

	}
	if len(h.buf) > 0 {
		if len(h.buf) > len(b) {
			n := copy(b, h.buf[:len(b)])
			h.buf = h.buf[n:]
			return n, nil
		} else {
			n := copy(b, h.buf)
			pool.PutBuf(h.forgc)
			h.buf = nil
			h.forgc = nil
			return n, nil
		}
	}
	return h.ICtxConn.Read(b)
}

func (h *HTTP) Write(b []byte) (int, error) {
	if h.flag&flagFirstWrite == 0 {
		key := make([]byte, 16)
		rand.Read(key)
		buf := bytes.NewBuffer([]byte(fmt.Sprintf(reqTemplete, h.method, h.host, h.host, rand.Int()%66, rand.Int()&3,
			base64.URLEncoding.EncodeToString(key), len(b))))
		buf.Write(b)
		_, err := buf.WriteTo(h.ICtxConn)
		h.flag = h.flag | flagFirstWrite
		return len(b), err
	}
	return h.ICtxConn.Write(b)
}
