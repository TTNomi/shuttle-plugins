package main

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sipt/shuttle/plugins/ss/obfs"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/conn"
	"github.com/sipt/shuttle/dns"
	"github.com/sipt/shuttle/plugins/ss/ciphers"
	"github.com/sipt/shuttle/server"
	"github.com/sirupsen/logrus"
)

const (
	ShadowSocks = "ss"

	ssKeyMethod   = "method"
	ssKeyPassword = "password"
	ssKeyObfsTyp  = "obfs"
)

func init() {
	logrus.Infof("plugin [%s] load success", ShadowSocks)
	server.Register(ShadowSocks, newSsServer)
}

func newSsServer(name, addr string, port int, params map[string]string, dnsHandle dns.Handle) (s server.IServer, e error) {
	ss := &ssServer{
		RWMutex:   &sync.RWMutex{},
		rtt:       make(map[string]time.Duration),
		name:      name,
		addr:      addr,
		port:      port,
		ip:        net.ParseIP(addr),
		dnsHandle: dnsHandle,
	}
	var ok bool
	if ss.method, ok = params[ssKeyMethod]; !ok || len(ss.method) == 0 {
		return nil, errors.Errorf("server [typ:ss] [name:%s] missing params [method]", name)
	}
	if ss.password, ok = params[ssKeyPassword]; !ok || len(ss.password) == 0 {
		return nil, errors.Errorf("server [typ:ss] [name:%s] missing params [password]", name)
	}
	if obfsTyp, ok := params[ssKeyObfsTyp]; ok && len(obfsTyp) > 0 {
		ss.obfsFunc, e = obfs.Get(obfsTyp, params)
		if e != nil {
			return nil, errors.Wrapf(e, "server [typ:ss] [name:%s] init obfs failed", name)
		}
	}
	return ss, nil
}

func ApplyConfig(_ map[string]string) error {
	return nil
}

type ssServer struct {
	server.IServer // just for not implement: TestRtt
	rtt            map[string]time.Duration
	*sync.RWMutex
	name      string
	addr      string
	ip        net.IP
	port      int
	dnsHandle dns.Handle
	method    string
	password  string
	obfsFunc  obfs.HandleFunc
}

func (s *ssServer) Typ() string {
	return ShadowSocks
}
func (s *ssServer) Name() string {
	return s.name
}
func (s *ssServer) SetRtt(key string, rtt time.Duration) {
	s.Lock()
	defer s.Unlock()
	s.rtt[key] = rtt
}
func (s *ssServer) Rtt(key string) time.Duration {
	s.RLock()
	defer s.RUnlock()
	return s.rtt[key]
}

func (s *ssServer) Dial(ctx context.Context, network string, info server.Info, dial conn.DialFunc) (conn.ICtxConn, error) {
	rawAddr, err := MarshalAddr(info.Domain(), info.IP(), info.Port())
	if err != nil {
		return nil, errors.Wrapf(err, "[ss] format addr failed, {domain:%s, ip:%s, port:%d}",
			info.Domain(), info.IP(), info.Port())
	}
	var s_host string
	if len(s.ip) == 0 {
		d := s.dnsHandle(ctx, s.addr)
		s_host = d.CurrentIP.String()
	} else {
		s_host = s.ip.String()
	}
	var sc conn.ICtxConn
	switch network {
	case "tcp":
		sc, err = s.dialTCP(ctx, network, s_host, strconv.Itoa(s.port), dial)
	case "udp":
		sc, err = s.dialUDP(ctx, network, s_host, strconv.Itoa(s.port), dial)
	default:
		return nil, errors.Errorf("[ss] not support network: %s", network)
	}
	defer func() {
		if err != nil && sc != nil {
			_ = sc.Close()
		}
	}()
	if err != nil {
		return nil, errors.Wrapf(err, "[ss] dial [%s] to server{domain:%s, ip:%s, port:%d} failed",
			network, info.Domain(), info.IP(), info.Port())
	}
	if s.obfsFunc != nil {
		sc, err = s.obfsFunc(sc)
		if err != nil {
			return nil, errors.Wrapf(err, "[ss:%s] wrap obfs failed", s.name)
		}
	}
	sc, err = ciphers.CipherDecorate(s.password, s.method, sc)
	if err != nil {
		return nil, errors.Wrapf(err, "[ss] decorate cipher[%s] failed", s.method)
	}
	n, err := sc.Write(rawAddr)
	if err != nil || n != len(rawAddr) {
		return nil, errors.Wrapf(err, "[ss] fail to write raw address to server")
	}
	return sc, nil
}

func (s *ssServer) dialTCP(ctx context.Context, network, host, port string, dial conn.DialFunc) (conn.ICtxConn, error) {
	return dial(ctx, network, host, port)
}

func (s *ssServer) dialUDP(ctx context.Context, network, host, port string, dial conn.DialFunc) (conn.ICtxConn, error) {
	return nil, nil
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
