package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/sipt/shuttle/plugins/vmess"
	"github.com/sipt/shuttle/plugins/vmess/websocket"
)

func main() {
	ctx := context.Background()
	conn, err := websocket.DialWebsocket(ctx, "/", http.Header{
		"Host": {"3874e11169.xwdsh.xyz"},
	}, vmess.Destination{
		Network: vmess.Network_TCP,
		Address: vmess.IPAddress([]byte{120, 79, 5, 78}),
		Port:    153,
	}, false)
	if err != nil {
		panic(err)
	}

	&vmess.Conn{}

	client := crypto.NewClientSession(protocol.DefaultIDHash)
	id, err := uuid.ParseString("d64218e2-2fc8-31fd-ba57-9514c45527d1")
	if err != nil {
		panic(err)
	}
	protoID := protocol.NewID(id)
	req := &protocol.RequestHeader{
		Version:  1,
		Command:  protocol.RequestCommandTCP,
		Option:   bitmask.Byte(0),
		Security: protocol.SecurityType_AES128_GCM,
		Port:     80,
		Address:  net.DomainAddress("www.github.com"),
		User: &protocol.MemoryUser{
			Account: &vmess.MemoryAccount{
				ID:       protoID,
				AlterIDs: protocol.NewAlterIDs(protoID, uint16(64)),
				Security: protocol.SecurityType_AUTO,
			},
		},
	}
	client.EncodeRequestBody(req, conn)
	w := client.EncodeRequestBody(req, conn)
	mb, err := buf.ReadFrom(bytes.NewBufferString("GET http://www.github.com/ HTTP/1.1\r\n\r\n"))
	if err != nil {
		panic(err)
	}
	err = w.WriteMultiBuffer(mb)
	if err != nil {
		panic(err)
	}
	r := client.DecodeResponseBody(req, conn)
	mb, err = r.ReadMultiBuffer()
	if err != nil {
		panic(err)
	}
	fmt.Println(mb.String())
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
