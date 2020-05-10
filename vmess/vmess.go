package vmess

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sipt/shuttle/plugins/vmess/common"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/dns"
	"github.com/sipt/shuttle/plugins/vmess/websocket"
	"github.com/sipt/shuttle/server"
	"github.com/sirupsen/logrus"
)

const (
	VMess = "vmess"

	KeyID       = "id"
	KeyMethod   = "method"
	KeyProtocol = "protocol"
	KeyPath     = "path"
	KeyHeader   = "header"
	KeyUDPRelay = "udp-relay"
)

func init() {
	logrus.Infof("plugin [%s] load success", VMess)
	server.Register(VMess, newVMessServer)
}

func newVMessServer(name, addr string, port int, params map[string]string, dnsHandle dns.Handle) (s server.IServer, e error) {
	vmess := &Server{
		RWMutex:   &sync.RWMutex{},
		rtt:       make(map[string]time.Duration),
		name:      name,
		addr:      addr,
		port:      port,
		ip:        net.ParseIP(addr),
		dnsHandle: dnsHandle,
	}
	var ok bool
	if id, ok := params[KeyID]; !ok || len(id) == 0 {
		return nil, errors.Errorf("server [typ:vmess] [name:%s] missing params [id]", name)
	} else {
		vmess.id, e = uuid.Parse(id)
		if e != nil {
			return nil, errors.Wrapf(e, "server [typ:vmess] [name:%s] [id: %s] invalid", name, id)
		}
	}
	if method, ok := params[KeyMethod]; !ok || len(method) == 0 {
		return nil, errors.Errorf("server [typ:vmess] [name:%s] missing params [method]", name)
	} else {
		if vmess.method, ok = common.SecurityType_value[method]; ok {
			if runtime.GOARCH == "amd64" || runtime.GOARCH == "s390x" || runtime.GOARCH == "arm64" {
				vmess.method = common.SecurityType_AES128_GCM
			} else {
				vmess.method = common.SecurityType_CHACHA20_POLY1305
			}
		}
	}
	if vmess.path, ok = params[KeyPath]; !ok || len(vmess.path) == 0 {
		vmess.path = "/"
	}
	if vmess.protocol, ok = params[KeyProtocol]; !ok || len(vmess.protocol) == 0 {
		return nil, errors.Errorf("server [typ:vmess] [name:%s] missing params [protocol]", name)
	} else {
		switch vmess.protocol {
		case "ws", "wss":
		default:
			return nil, errors.Errorf("server [typ:vmess] [name:%s] not support [protocol:%s]", name, vmess.protocol)
		}
	}
	if header, ok := params[KeyHeader]; ok && len(header) > 0 {
		headers := strings.Split(header, ";")
		for _, v := range headers {
			vs := strings.Split(v, ":")
			vmess.header.Set(strings.TrimSpace(vs[0]), strings.TrimSpace(vs[1]))
		}
	}
	vmess.udpRelay = params[KeyUDPRelay] == "on"
	return vmess, nil
}

func ApplyConfig(_ map[string]string) error {
	return nil
}

type Server struct {
	server.IServer // just for not implement: TestRtt
	rtt            map[string]time.Duration
	*sync.RWMutex
	name      string
	addr      string
	ip        net.IP
	port      int
	dnsHandle dns.Handle
	id        uuid.UUID
	path      string
	method    common.SecurityType
	protocol  string
	header    http.Header
	udpRelay  bool
}

func (s *Server) Typ() string {
	return VMess
}
func (s *Server) Name() string {
	return s.name
}
func (s *Server) SetRtt(key string, rtt time.Duration) {
	s.Lock()
	defer s.Unlock()
	s.rtt[key] = rtt
}
func (s *Server) Rtt(key string) time.Duration {
	s.RLock()
	defer s.RUnlock()
	return s.rtt[key]
}
func (s *Server) UdpRelay() bool {
	return s.udpRelay
}
func (s *Server) Dial(ctx context.Context, network string, info server.Info, dial conn.DialFunc) (conn.ICtxConn, error) {
	if network == "udp" && !s.udpRelay {
		return nil, errors.Errorf("[ss:%s] not support udp", s.name)
	}
	var s_host string
	if len(s.ip) == 0 {
		d := s.dnsHandle(ctx, s.addr)
		s_host = d.CurrentIP.String()
	} else {
		s_host = s.ip.String()
	}
	sc, err := websocket.DialWebsocket(ctx, s.protocol, s.path, s.header, s_host, strconv.Itoa(s.port), dial)
	defer func() {
		if err != nil && sc != nil {
			_ = sc.Close()
		}
	}()
	if err != nil {
		return nil, errors.Wrapf(err, "[vmess] dial [%s] to server{domain:%s, ip:%s, port:%d} failed",
			network, info.Domain(), info.IP(), info.Port())
	}
	protoID := NewID(s.id)
	dest := &Destination{
		Port:    Port(info.Port()),
		Network: network,
	}
	if len(info.Domain()) > 0 {
		dest.Address = DomainAddress(info.Domain())
	} else {
		dest.Address = IPAddress(info.IP())
	}

	sc, err = NewConn(sc, dest, &Account{
		ID:       protoID,
		AlterIDs: NewAlterIDs(protoID, uint16(64)),
		Security: s.method,
	})
	return sc, nil
}
