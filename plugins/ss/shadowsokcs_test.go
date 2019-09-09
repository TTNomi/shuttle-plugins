package main

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/pkg/pool"
	"github.com/stretchr/testify/assert"
)

func TestSsServer_Dial(t *testing.T) {
	//ss, err := newSsServer("HK-WTT-B", "192.168.99.100", 6443, map[string]string{
	//	"method":      "xchacha20-ietf-poly1305",
	//	"password":    "test123",
	//	"obfs":        "http",
	//	"http-host":   "world.taobao.com",
	//	"http-method": "GET",
	//}, nil)
	ss, err := newSsServer("HK-WTT-B", "47.107.25.183", 152, map[string]string{
		"method":   "chacha20-ietf-poly1305",
		"password": "UrTAdN",
		"obfs":     "tls",
		"tls-host": "2d99911169.wns.windows.com",
	}, nil)
	assert.NoError(t, err)
	sc, err := ss.Dial(context.Background(), "tcp", &request{
		domain: "www.bing.com",
		port:   80,
	}, conn.DefaultDial)
	assert.NoError(t, err)
	_, err = sc.Write([]byte("GET http://www.bing.com/ HTTP/1.1\r\nHost: www.bing.com\r\n\r\n"))
	assert.NoError(t, err)
	data := pool.GetBuf()
	n, err := sc.Read(data)
	assert.NoError(t, err)
	fmt.Println(string(data[:n]))
}

type request struct {
	domain string
	ip     net.IP
	port   int
}

func (r *request) Domain() string {
	return r.domain
}
func (r *request) IP() net.IP {
	return r.ip
}
func (r *request) Port() int {
	return r.port
}
