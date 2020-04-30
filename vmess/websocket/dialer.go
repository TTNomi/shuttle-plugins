package websocket

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sipt/shuttle/plugins/vmess"
)

func DialWebsocket(ctx context.Context, path string, header http.Header, dest vmess.Destination, useTLS bool) (net.Conn, error) {
	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return net.Dial(dest.Network.SystemString(), dest.NetAddr())
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	//if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
	//	protocol = "wss"
	//	dialer.TLSClientConfig = config.GetTLSConfig(tls.WithDestination(dest))
	//}

	host := dest.NetAddr()
	if (protocol == "ws" && dest.Port == 80) || (protocol == "wss" && dest.Port == 443) {
		host = dest.Address.String()
	}
	uri := protocol + "://" + host + path

	conn, resp, err := dialer.Dial(uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, fmt.Errorf("failed to dial to (%s): %s, err: %s", uri, reason, err.Error())
	}

	return newConnection(conn, conn.RemoteAddr()), nil
}
