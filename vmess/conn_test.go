package vmess

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func Test(t *testing.T) {
	ctx := context.Background()
	conn, err := DialWebsocket(ctx, "/ray", http.Header{}, Destination{
		Network: Network_TCP,
		Address: IPAddress([]byte{127, 0, 0, 1}),
		Port:    8877,
	}, false)
	if err != nil {
		panic(err)
	}

	id, err := uuid.Parse("937a376b-1723-40de-9815-3bcee70cc8b8")
	if err != nil {
		panic(err)
	}

	protoID := NewID(id)
	sc, err := NewConn(conn, &Destination{
		Address: DomainAddress("www.baidu.com"),
		Port:    80,
		Network: Network_TCP,
	}, &Account{
		ID:       protoID,
		AlterIDs: NewAlterIDs(protoID, uint16(64)),
		Security: SecurityType_AES128_GCM,
	})
	if err != nil {
		panic(err)
	}

	err = sc.sendRequestHeader()
	if err != nil {
		panic(err)
	}

	_, err = sc.Write([]byte("GET http://www.baidu.com/ HTTP/1.1\r\n\r\n"))
	if err != nil {
		panic(err)
	}

	b := make([]byte, 2014)
	_, err = conn.Read(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}

func DialWebsocket(ctx context.Context, path string, header http.Header, dest Destination, useTLS bool) (net.Conn, error) {
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

// connection is a wrapper for net.Conn over WebSocket connection.
type connection struct {
	conn       *websocket.Conn
	reader     io.Reader
	remoteAddr net.Addr
}

func newConnection(conn *websocket.Conn, remoteAddr net.Addr) *connection {
	return &connection{
		conn:       conn,
		remoteAddr: remoteAddr,
	}
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (c *connection) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.conn.NextReader()
	if err != nil {
		return nil, err
	}
	c.reader = reader
	return reader, nil
}

// Write implements io.Writer.
func (c *connection) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *connection) Close() error {
	var errors []string
	if err := c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5)); err != nil {
		errors = append(errors, err.Error())
	}
	if err := c.conn.Close(); err != nil {
		errors = append(errors, err.Error())
	}
	if len(errors) > 0 {
		return fmt.Errorf("failed to close connection: %s", strings.Join(errors, ","))
	}
	return nil
}

func (c *connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

//
//func dail(ctx context.Context, uri string) (net.Conn, error) {
//	dialer := &websocket.Dialer{
//		NetDial: func(network, addr string) (net.Conn, error) {
//			return net.Dial(network, addr)
//		},
//		ReadBufferSize:   4 * 1024,
//		WriteBufferSize:  4 * 1024,
//		HandshakeTimeout: time.Second * 8,
//	}
//	conn, resp, err := dialer.Dial(uri, http.Header{})
//	if err != nil {
//		if resp != nil {
//			return nil, fmt.Errorf("connect to server failed: %s", resp.Status)
//		}
//		return nil, err
//	}
//	return &websocketConn{
//		Conn: conn,
//	}, nil
//}
//
//type websocketConn struct {
//	*websocket.Conn
//	reader     io.Reader
//	remoteAddr net.Addr
//}
//
//func (w *websocketConn) RemoteAddr() net.Addr {
//	return w.remoteAddr
//}
//
//func (w *websocketConn) getReader() (io.Reader, error) {
//	if w.reader != nil {
//		return w.reader, nil
//	}
//
//	_, reader, err := w.NextReader()
//	if err != nil {
//		return nil, err
//	}
//	w.reader = reader
//	return w.reader, nil
//}
//
//func (w *websocketConn) Write(b []byte) (int, error) {
//	err := w.Conn.WriteMessage(websocket.BinaryMessage, b)
//	if err != nil {
//		return 0, err
//	}
//	return len(b), err
//}
//
//func (w *websocketConn) Read(b []byte) (int, error) {
//	for {
//		reader, err := w.getReader()
//		if err != nil {
//			return 0, err
//		}
//
//		nBytes, err := reader.Read(b)
//		if errors.Cause(err) == io.EOF {
//			w.reader = nil
//			continue
//		}
//		return nBytes, err
//	}
//}
//
//func (w *websocketConn) Close() error {
//	var errors []interface{}
//	if err := w.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5)); err != nil {
//		errors = append(errors, err)
//	}
//	if err := w.Close(); err != nil {
//		errors = append(errors, err)
//	}
//	if len(errors) > 0 {
//		return fmt.Errorf("failed to close connection: %s", serial.Concat(errors...))
//	}
//	return nil
//}
//
//func (w *websocketConn) SetDeadline(t time.Time) error {
//	if err := w.SetReadDeadline(t); err != nil {
//		return err
//	}
//	return w.SetWriteDeadline(t)
//}
