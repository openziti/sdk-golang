/*
	Copyright 2019 Netfoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package ziti

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/ziti-foundation/channel2"
	"github.com/netfoundry/ziti-foundation/common/constants"
	"github.com/netfoundry/ziti-foundation/identity/identity"
	"github.com/netfoundry/ziti-foundation/transport"
	"github.com/netfoundry/ziti-foundation/util/info"
	"github.com/netfoundry/ziti-sdk-golang/ziti/config"
	"github.com/netfoundry/ziti-sdk-golang/ziti/edge"
	"github.com/netfoundry/ziti-sdk-golang/ziti/internal/edge_impl"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Context interface {
	Authenticate() error
	Dial(serviceName string) (net.Conn, error)
	Listen(serviceName string) (net.Listener, error)
	GetServiceId(serviceName string) (string, bool, error)
	GetServices() ([]edge.Service, error)
	GetSession(id string) (*edge.Session, error)
	GetBindSession(id string) (*edge.Session, error)

	// Close closes any connections open to edge routers
	Close()
}

var authUrl, _ = url.Parse("/authenticate?method=cert")
var servicesUrl, _ = url.Parse("/services")
var sessionUrl, _ = url.Parse("/sessions")

type contextImpl struct {
	config                  *config.Config
	initDone                sync.Once
	edgeRouterConnFactories map[string]edge.ConnFactory
	connMutex               sync.Mutex

	id          identity.Identity
	zitiUrl     *url.URL
	tlsCtx      *tls.Config
	clt         http.Client
	apiSession  *edge.ApiSession
	servicesMtx sync.RWMutex
	services    []edge.Service
	sessions    sync.Map
}

func NewContext() Context {
	return &contextImpl{edgeRouterConnFactories: make(map[string]edge.ConnFactory)}
}

func NewContextWithConfig(config *config.Config) Context {
	return &contextImpl{edgeRouterConnFactories: make(map[string]edge.ConnFactory), config: config}
}

func (context *contextImpl) ensureConfigPresent() error {
	if context.config != nil {
		return nil
	}

	const configEnvVarName = "ZITI_SDK_CONFIG"
	// If configEnvVarName is set, try to use it.
	// The calling application may override this by calling NewContextWithConfig
	confFile := os.Getenv(configEnvVarName)

	if confFile == "" {
		return errors.Errorf("unable to configure ziti as config environment variable %v not populated", configEnvVarName)
	}

	logrus.Infof("loading Ziti configuration from %s", confFile)
	cfg, err := config.NewFromFile(confFile)
	if err != nil {
		return errors.Errorf("error loading config file specified by ${%s}: %v", configEnvVarName, err)
	}
	context.config = cfg
	return nil
}

func (context *contextImpl) initialize() error {
	var err error
	context.initDone.Do(func() {
		err = context.initializer()
	})
	return err
}

func (context *contextImpl) initializer() error {
	err := context.ensureConfigPresent()
	if err != nil {
		return err
	}
	context.zitiUrl, _ = url.Parse(context.config.ZtAPI)

	id, err := identity.LoadIdentity(context.config.ID)
	if err != nil {
		return err
	}

	context.id = id
	context.tlsCtx = id.ClientTLSConfig()
	context.clt = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: context.tlsCtx,
		},
		Timeout: 30 * time.Second,
	}

	if err = context.Authenticate(); err != nil {
		return err
	}

	// get services
	if context.services, err = context.getServices(); err != nil {
		return err
	}

	return nil
}

func (context *contextImpl) Authenticate() error {
	logrus.Info("attempting to authenticate")
	context.sessions = sync.Map{}

	req := new(bytes.Buffer)
	json.NewEncoder(req).Encode(info.GetSdkInfo())
	resp, err := context.clt.Post(context.zitiUrl.ResolveReference(authUrl).String(), "application/json", req)
	if err != nil {
		pfxlog.Logger().Errorf("failure to post auth %+v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logrus.Fatal("failed to authenticate with ZT controller")
	}

	apiSessionResp := edge.ApiSession{}

	_, err = edge.ApiResponseDecode(&apiSessionResp, resp.Body)
	if err != nil {
		return err
	}
	logrus.
		WithField("token", apiSessionResp.Token).
		WithField("id", apiSessionResp.Id).
		Debugf("Got api session: %v", apiSessionResp)
	context.apiSession = &apiSessionResp

	return nil
}

func (context *contextImpl) Dial(serviceName string) (net.Conn, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initilize context: (%v)", err)
	}
	id, ok := context.getServiceId(serviceName)
	if !ok {
		return nil, errors.Errorf("service '%s' not found in ZT", serviceName)
	}

	var conn net.Conn
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		ns, err := context.GetSession(id)
		if err != nil {
			return nil, err
		}
		conn, err = context.dialSession(serviceName, ns)
		if err != nil && attempt == 0 {
			if strings.Contains(err.Error(), "closed") {
				context.deleteSession(id)
				continue
			}
		}
		return conn, err
	}
	return nil, errors.Errorf("unable to dial service '%s' (%v)", serviceName, err)
}

func (context *contextImpl) dialSession(service string, session *edge.Session) (net.Conn, error) {
	edgeConnFactory, err := context.getEdgeRouterConnFactory(session)
	if err != nil {
		return nil, err
	}
	edgeConn := edgeConnFactory.NewConn(service)
	return edgeConn.Connect(session)
}

func (context *contextImpl) Listen(serviceName string) (net.Listener, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%w)", err)
	}

	if id, ok, _ := context.GetServiceId(serviceName); ok {
		for attempt := 0; attempt < 2; attempt++ {
			ns, err := context.GetBindSession(id)
			if err != nil {
				return nil, err
			}
			listener, err := context.listenSession(ns, serviceName)
			if err != nil && attempt == 0 {
				if strings.Contains(err.Error(), "closed") {
					context.deleteSession(id)
					continue
				}
			}
			return listener, err
		}
	}
	return nil, errors.Errorf("service '%s' not found in ZT", serviceName)
}

func (context *contextImpl) listenSession(session *edge.Session, serviceName string) (net.Listener, error) {
	edgeConnFactory, err := context.getEdgeRouterConnFactory(session)
	if err != nil {
		return nil, err
	}
	edgeConn := edgeConnFactory.NewConn(serviceName)
	return edgeConn.Listen(session, serviceName)
}

func (context *contextImpl) getEdgeRouterConnFactory(session *edge.Session) (edge.ConnFactory, error) {
	logger := pfxlog.Logger().WithField("ns", session.Token)

	if len(session.EdgeRouters) == 0 {
		return nil, errors.New("no edge routers available")
	}
	edgeRouter := session.EdgeRouters[0]
	ingressUrl := edgeRouter.Urls["tls"]

	context.connMutex.Lock()
	defer context.connMutex.Unlock()

	// remove any closed connections
	for key, val := range context.edgeRouterConnFactories {
		if val.IsClosed() {
			delete(context.edgeRouterConnFactories, key)
		}
	}

	if edgeConn, found := context.edgeRouterConnFactories[ingressUrl]; found {
		return edgeConn, nil
	}

	ingAddr, err := transport.ParseAddress(ingressUrl)
	if err != nil {
		return nil, err
	}

	id := context.id
	dialer := channel2.NewClassicDialer(identity.NewIdentity(id), ingAddr, map[int32][]byte{
		edge.SessionTokenHeader: []byte(context.apiSession.Token),
	})

	ch, err := channel2.NewChannel("ziti-sdk", dialer, nil)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	edgeConn := edge_impl.NewEdgeConnFactory(ch)
	context.edgeRouterConnFactories[ingressUrl] = edgeConn
	return edgeConn, nil
}

func (context *contextImpl) GetServiceId(name string) (string, bool, error) {
	if err := context.initialize(); err != nil {
		return "", false, errors.Errorf("failed to initilize context: (%v)", err)
	}

	id, found := context.getServiceId(name)
	return id, found, nil
}

func (context *contextImpl) getServiceId(name string) (string, bool) {
	context.servicesMtx.RLock()
	defer context.servicesMtx.RUnlock()

	for _, s := range context.services {
		if s.Name == name {
			return s.Id, true
		}
	}
	return "", false
}

func (context *contextImpl) GetServices() ([]edge.Service, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initilize context: (%v)", err)
	}
	return context.getServices()
}

func (context *contextImpl) getServices() ([]edge.Service, error) {
	servReq, _ := http.NewRequest("GET", context.zitiUrl.ResolveReference(servicesUrl).String(), nil)

	if context.apiSession.Token == "" {
		return nil, errors.New("api session token is empty")
	} else {
		pfxlog.Logger().Debugf("using api session token %v", context.apiSession.Token)
	}
	servReq.Header.Set(constants.ZitiSession, context.apiSession.Token)
	pgOffset := 0
	pgLimit := 100
	servicesMap := make(map[string]edge.Service)

	for {
		q := servReq.URL.Query()
		q.Set("limit", strconv.Itoa(pgLimit))
		q.Set("offset", strconv.Itoa(pgOffset))
		servReq.URL.RawQuery = q.Encode()
		resp, err := context.clt.Do(servReq)

		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			if body, err := ioutil.ReadAll(resp.Body); err != nil {
				pfxlog.Logger().Debugf("error response: %v", body)
			}
			return nil, errors.New("unauthorized")
		}

		if err != nil {
			return nil, err
		}

		s := &[]edge.Service{}
		meta, err := edge.ApiResponseDecode(s, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if meta == nil {
			// shouldn't happen
			return nil, errors.New("nil metadata in response to GET /services")
		}
		if meta.Pagination == nil {
			return nil, errors.New("nil pagination in response to GET /services")
		}

		for _, svc := range *s {
			servicesMap[svc.Name] = svc
		}

		pgOffset += pgLimit
		if pgOffset >= meta.Pagination.TotalCount {
			break
		}
	}

	services := make([]edge.Service, len(servicesMap))
	i := 0
	for _, s := range servicesMap {
		services[i] = s
		i++
	}
	context.servicesMtx.Lock()
	context.services = services
	context.servicesMtx.Unlock()
	return services, nil
}

func (context *contextImpl) GetSession(id string) (*edge.Session, error) {
	return context.getSession(id, false)
}

func (context *contextImpl) GetBindSession(id string) (*edge.Session, error) {
	return context.getSession(id, true)
}

func (context *contextImpl) getSession(id string, bind bool) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}
	val, ok := context.sessions.Load(id)
	if ok {
		return val.(*edge.Session), nil
	}
	body := fmt.Sprintf(`{"serviceId":"%s", "hosting": %s}`, id, strconv.FormatBool(bind))
	reqBody := bytes.NewBufferString(body)

	url := context.zitiUrl.ResolveReference(sessionUrl).String()
	pfxlog.Logger().Debugf("requesting session from %v", url)
	req, _ := http.NewRequest("POST", url, reqBody)
	req.Header.Set(constants.ZitiSession, context.apiSession.Token)
	req.Header.Set("Content-Type", "application/json")

	logrus.WithField("service_id", id).Debug("requesting session")
	resp, err := context.clt.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to create session: %s\n%s", resp.Status, string(respBody))
	}

	session := new(edge.Session)
	_, err = edge.ApiResponseDecode(session, resp.Body)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("failed to decode session response")
		return nil, err
	}
	context.sessions.Store(id, session)

	return session, nil
}

func (context *contextImpl) deleteSession(id string) {
	context.sessions.Delete(id)
}

func (context *contextImpl) Close() {
	logger := pfxlog.Logger()

	context.connMutex.Lock()
	defer context.connMutex.Unlock()

	// remove any closed connections
	for key, val := range context.edgeRouterConnFactories {
		if !val.IsClosed() {
			if err := val.Close(); err != nil {
				logger.WithError(err).Error("error while closing connection")
			}
		}
		delete(context.edgeRouterConnFactories, key)
	}
}
