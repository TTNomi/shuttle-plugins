package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/dns"
	"github.com/sipt/shuttle/pkg/pool"
	"github.com/sipt/shuttle/server"
	"github.com/sirupsen/logrus"
)

const (
	Trojan = "trojan"

	KeyPassword = "password"
	KeyUDPRelay = "udp-relay"
)

func init() {
	logrus.Infof("plugin [%s] load success", Trojan)
	server.Register(Trojan, newTrojanServer)
}

func newTrojanServer(name, addr string, port int, params map[string]string, dnsHandle dns.Handle) (s server.IServer, e error) {
	server := &Server{
		RWMutex:   &sync.RWMutex{},
		rtt:       make(map[string]time.Duration),
		name:      name,
		addr:      addr,
		port:      port,
		ip:        net.ParseIP(addr),
		dnsHandle: dnsHandle,
	}
	var ok bool
	if server.password, ok = params[KeyPassword]; !ok || len(server.password) == 0 {
		return nil, errors.Errorf("server [typ:trojan] [name:%s] missing params [password]", name)
	}
	server.udpRelay = params[KeyUDPRelay] == "on"
	return server, nil
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
	password  string
	udpRelay  bool
}

func (s *Server) Typ() string {
	return Trojan
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
	sc, err := dial(ctx, "tcp", s_host, strconv.Itoa(s.port))
	defer func() {
		if err != nil && sc != nil {
			_ = sc.Close()
		}
	}()
	if err != nil {
		return nil, errors.Wrapf(err, "[trojan] dial [%s] to server{domain:%s, ip:%s, port:%d} failed",
			network, info.Domain(), info.IP(), info.Port())
	}
	c := conn.NewConn(tls.Client(sc, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}), sc.GetContext())
	err = sendHeader(c, network, info, s.password)
	if err != nil {
		return nil, errors.Wrapf(err, "[trojan] send header to server [%s]{domain:%s, ip:%s, port:%d} failed",
			network, info.Domain(), info.IP(), info.Port())
	}
	if network == "udp" {
		rawAddr, err := MarshalAddr(info.Domain(), info.IP(), info.Port())
		if err != nil {
			return nil, errors.Wrapf(err, "[trojan] format addr failed, {domain:%s, ip:%s, port:%d}",
				info.Domain(), info.IP(), info.Port())
		}
		c = &updConn{
			ICtxConn: c,
			index:    len(rawAddr),
			rawAddr:  append(rawAddr, 0, 0, 0x0d, 0x0a),
		}
	}
	return c, nil
}

func sendHeader(sc conn.ICtxConn, network string, info server.Info, password string) error {
	rawAddr, err := MarshalAddr(info.Domain(), info.IP(), info.Port())
	if err != nil {
		return errors.Wrapf(err, "[trojan] format addr failed, {domain:%s, ip:%s, port:%d}",
			info.Domain(), info.IP(), info.Port())
	}
	hash := sha256.New224()
	hash.Write([]byte(password))
	val := hash.Sum(nil)
	password = hex.EncodeToString(val[:])
	b := pool.GetBuf()
	defer pool.PutBuf(b)
	buf := bytes.NewBuffer(b[:0])
	buf.Write([]byte(password))
	buf.Write([]byte{0x0d, 0x0a})
	if network == "tcp" {
		buf.WriteByte(0x01)
	} else {
		buf.WriteByte(0x03)
	}
	buf.Write(rawAddr)
	buf.Write([]byte{0x0d, 0x0a})
	_, err = sc.Write(buf.Bytes())
	return err
}

// MarshalAddr
func MarshalAddr(host string, ip net.IP, port int) ([]byte, error) {
	b := make([]byte, 1, 16)
	if host != "" {
		if len(host) > 255 {
			return nil, errors.New("fqdn too long")
		}
		b[0] = 0x03
		b = append(b, byte(len(host)))
		b = append(b, host...)
	} else if ip4 := ip.To4(); ip4 != nil {
		b[0] = 0x01
		b = append(b, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		b[0] = 0x04
		b = append(b, ip6...)
	} else {
		return nil, errors.New("unknown address type")
	}
	b = append(b, byte(port>>8), byte(port))
	return b, nil
}

type updConn struct {
	rawAddr []byte
	index   int
	conn.ICtxConn
}

func (c *updConn) Read(b []byte) (int, error) {
	n, err := c.ICtxConn.Read(b)
	r := b[:n]
	switch r[0] {
	case 0x01:
		r = r[1+net.IPv4len:]
	case 0x03:
		l := binary.BigEndian.Uint16(r[1:3])
		r = r[2+l:]
	case 0x04:
		r = r[1+net.IPv6len:]
	default:
	}
	r = r[6:] // 2(port)+2(len)+2(0x0d,0x0a)
	n = copy(b, r)
	return n, err
}

func (c *updConn) Write(b []byte) (int, error) {
	binary.BigEndian.PutUint16(c.rawAddr[c.index:c.index+2], uint16(len(b)))
	_, err := c.ICtxConn.Write(c.rawAddr)
	if err != nil {
		return 0, err
	}
	n, err := c.ICtxConn.Write(b)
	return n, err
}
