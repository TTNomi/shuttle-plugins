package websocket

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sipt/shuttle/conn"
)

func DialWebsocket(ctx context.Context, protocol, path string, header http.Header, addr, port string, dial conn.DialFunc) (conn.ICtxConn, error) {
	if port == "" || port == "0" {
		switch protocol {
		case "ws":
			port = "80"
		case "wss":
			port = "443"
		}
	}

	uri := protocol + "://" + net.JoinHostPort(addr, port) + path
	var scCtx conn.ICtxConn
	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var err error
			scCtx, err = dial(ctx, network, addr, port)
			return scCtx, err
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	if protocol == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	wc, resp, err := dialer.DialContext(ctx, uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, errors.Wrapf(err, "failed to dial to (%s): %s", uri, reason)
	}

	c := newConnection(wc, wc.RemoteAddr())
	return conn.NewConn(c, scCtx), nil
}
