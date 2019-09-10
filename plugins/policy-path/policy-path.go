package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sipt/shuttle/dns"
	"github.com/sipt/shuttle/group"
	"github.com/sipt/shuttle/server"
	"github.com/sirupsen/logrus"
)

const (
	TypDler = "dler-ss"

	ParamsKeyExpireSec   = "expire_sec"
	ParamsKeyInternalTyp = "internal_typ"
	ParamsKeyTestURI     = "test_url"
	ParamsKeyAPIPath     = "api_path"
	ParamsKeyAPIMethod   = "api_method"

	DefaultExpireSec = 600 * time.Second
	DefaultTestURL   = "http://www.gstatic.com/generate_204"
)

func init() {
	group.Register(TypDler, newDlerGroup)
}

func newDlerGroup(ctx context.Context, name string, params map[string]string, dnsHandle dns.Handle) (g group.IGroup, err error) {
	dg := &dlerGroup{
		RWMutex:   &sync.RWMutex{},
		dnsHandle: dnsHandle,
	}
	internalTyp := params[ParamsKeyInternalTyp]
	dg.IGroup, err = group.Get(ctx, internalTyp, name, params, dnsHandle)
	if err != nil {
		return nil, errors.Errorf("[group:%s] init failed: %s", name, err.Error())
	}
	if dg.testUrl == "" {
		dg.testUrl = DefaultTestURL
	} else if testUrl, err := url.Parse(dg.testUrl); err != nil || len(testUrl.Scheme) == 0 || len(testUrl.Hostname()) == 0 {
		err = errors.Errorf("[group: %s] [%s: %s] is invalid", name, ParamsKeyTestURI, dg.testUrl)
		return nil, err
	}
	api := params[ParamsKeyAPIPath]
	if len(api) == 0 {
		return nil, errors.Errorf("[group: %s] api path is empty", name)
	}
	method := params[ParamsKeyAPIMethod]
	if len(method) == 0 {
		method = http.MethodGet
	}
	// 超时更新时间（秒）
	expireSecStr := params[ParamsKeyExpireSec]
	var expireSec = DefaultExpireSec
	if len(expireSecStr) > 0 {
		var sec int
		sec, err = strconv.Atoi(expireSecStr)
		if err != nil {
			return nil, errors.Errorf("[group: %s] expire_sec invalid: %s", name, err.Error())
		}
		expireSec = time.Duration(sec) * time.Second
	}
	dg.req, err = http.NewRequest(method, api, nil)
	if err != nil {
		return nil, errors.Errorf("[group: %s] make request failed: %s", name, err.Error())
	}
	err = dg.refresh()
	if err != nil {
		return nil, errors.Errorf("[group: %s] download server config failed: %s", name, err.Error())
	}
	go func() {
		timer := time.NewTimer(expireSec)
		for {
			select {
			case <-timer.C:
			case <-ctx.Done():
				logrus.Infof("[group: %s] auto update servers stopped", name)
				return
			}
			err := dg.refresh()
			if err != nil {
				logrus.Errorf("[group: %s] auto update servers failed: %s", name, err.Error())
			}
			timer.Reset(expireSec)
		}
	}()
	return dg, nil
}

type dlerGroup struct {
	group.IGroup
	hash      string
	req       *http.Request
	dnsHandle dns.Handle
	testUrl   string
	*sync.RWMutex
}

func (d *dlerGroup) refresh() error {
	d.Lock()
	defer d.Unlock()
	data, err := downloadGroup(d.req)
	if err != nil {
		return errors.Errorf("[%s] download group failed: %s", d.Name(), err.Error())
	}
	logrus.WithField("resp", string(data)).Debug("download success")
	// changes ?
	newHash := fmt.Sprintf("%x", md5.Sum(data))
	if newHash == d.hash {
		logrus.WithField("group", d.Name()).Info("group is up to date (no change)")
		return nil
	}
	d.hash = newHash
	items, err := unmarshal(data)
	if err != nil {
		return errors.Errorf("[%s] download group failed: %s", d.Name(), err.Error())
	}

	servers := make([]group.IServerX, 0, len(items))
	for _, v := range items {
		s, err := server.Get(v.Type, v.Name, v.Server, v.Port, map[string]string{
			"obfs":      obfsMap[v.Advanced.Obfs],
			"obfs-host": v.Advanced.ObfsHost,
			"method":    v.Cipher,
			"password":  v.Password,
			"udp-relay": v.UDP,
		}, d.dnsHandle)
		if err != nil {
			return err
		}
		logrus.Debugf("[group: %s] [server: %s] init success", d.Name(), s.Name())
		s = server.NewRttServer(s, map[string]string{server.ParamsKeyTestURI: d.testUrl})
		servers = append(servers, group.WrapServer(s))
	}
	d.Clear()
	d.Append(servers)
	logrus.WithField("group", d.Name()).Info("group is up to date")
	return nil
}

func downloadGroup(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func unmarshal(data []byte) ([]*item, error) {
	buf := bufio.NewReader(bytes.NewBuffer(data))
	items := make([]*item, 0, 16)
	for {
		item := &item{}
		line, _, err := buf.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		l, r := split(line, '=')
		item.Name = strings.TrimSpace(string(l)) // name
		l, r = split(r, ',')
		item.Type = strings.TrimSpace(string(l)) // type
		l, r = split(r, ',')
		item.Server = strings.TrimSpace(string(l)) // server
		l, r = split(r, ',')
		item.Port, err = strconv.Atoi(strings.TrimSpace(string(l))) // port
		if err != nil {
			return nil, errors.Errorf("[server: %s] port to int failed: %s", item.Name, strings.TrimSpace(string(l)))
		}

		for len(r) > 0 {
			l, r = split(r, '=')
			k := strings.TrimSpace(string(l))
			l, r = split(r, ',')
			v := strings.TrimSpace(string(l))
			item.set(k, v)
		}
		items = append(items, item)
	}
	return items, nil
}

func split(b []byte, flag byte) (left, right []byte) {
	for i := range b {
		if b[i] == flag {
			return b[:i], b[i+1:]
		}
	}
	return b, nil
}

type response struct {
	Ret  int    `json:"ret"`
	Msg  string `json:"msg"`
	Data []item `json:"data"`
}

type item struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Cipher   string `json:"cipher"`
	Password string `json:"password"`
	Advanced struct {
		Obfs     string `json:"obfs"`
		ObfsHost string `json:"obfs-host"`
	} `json:"advanced"`
	UDP string `json:"udp"`
}

func (i *item) set(k, v string) {
	switch k {
	case "encrypt-method":
		i.Cipher = v
	case "password":
		i.Password = v
	case "obfs":
		i.Advanced.Obfs = v
	case "obfs-host":
		i.Advanced.ObfsHost = v
	case "udp-relay":
		i.UDP = "true"
	default:
	}
}

var obfsMap = map[string]string{
	"simple_obfs_http": "http",
	"simple_obfs_tls":  "tls",
}
