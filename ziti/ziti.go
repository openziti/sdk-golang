/*
	Copyright 2019 NetFoundry, Inc.

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
	errors2 "errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/common/constants"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/transport"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/impl"
	"github.com/openziti/sdk-golang/ziti/sdkinfo"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	LatencyCheckInterval = 30 * time.Second
)

type Context interface {
	Authenticate() error
	Dial(serviceName string) (edge.ServiceConn, error)
	Listen(serviceName string) (edge.Listener, error)
	ListenWithOptions(serviceName string, options *edge.ListenOptions) (edge.Listener, error)
	GetServiceId(serviceName string) (string, bool, error)
	GetServices() ([]edge.Service, error)
	GetService(serviceName string) (*edge.Service, bool)

	GetSession(id string) (*edge.Session, error)
	GetBindSession(id string) (*edge.Session, error)

	Metrics() metrics.Registry
	// Close closes any connections open to edge routers
	Close()
}

type AuthFailure struct {
	httpCode int
	msg      string
}

func (e AuthFailure) Error() string {
	return fmt.Sprintf("authentication failed with http status code %v and msg: %v", e.httpCode, e.msg)
}

type notAuthorized struct{}

func (e notAuthorized) Error() string {
	return fmt.Sprintf("not authorized")
}

var NotAuthorized = notAuthorized{}

type NotAccessible struct {
	httpCode int
	msg      string
}

func (e NotAccessible) Error() string {
	return fmt.Sprintf("unable to create session. http status code: %v, msg: %v", e.httpCode, e.msg)
}

var authUrl, _ = url.Parse("/authenticate?method=cert")
var currSess, _ = url.Parse("/current-api-session")
var servicesUrl, _ = url.Parse("/services")
var sessionUrl, _ = url.Parse("/sessions")

type contextImpl struct {
	config            *config.Config
	options           *config.Options
	initDone          sync.Once
	routerConnections cmap.ConcurrentMap

	id          identity.Identity
	zitiUrl     *url.URL
	tlsCtx      *tls.Config
	clt         http.Client
	apiSession  *edge.ApiSession

	services sync.Map // name -> Service
	sessions sync.Map // svcID:type -> Session

	metrics metrics.Registry
}

func (context *contextImpl) OnClose(factory edge.RouterConn) {
	logrus.Debugf("connection to router [%s] was closed", factory.Key())
	context.routerConnections.Remove(factory.Key())
}

func NewContext() Context {
	return NewContextWithConfig(nil)
}

func NewContextWithConfig(cfg *config.Config) Context {
	return NewContextWithOpts(cfg, nil)
}

func NewContextWithOpts(cfg *config.Config, options *config.Options) Context {
	if options == nil {
		options = config.DefaultOptions
	}

	return &contextImpl{
		routerConnections: cmap.New(),
		config:            cfg,
		options:           options,
	}
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
	go context.runSessionRefresh()

	metricsTags := map[string]string{
		"srcId": context.apiSession.Identity.Id,
	}
	context.metrics = metrics.NewRegistry(context.apiSession.Identity.Name, metricsTags, LatencyCheckInterval, nil)

	// get services
	if services, err := context.getServices(); err != nil {
		return err
	} else {
		context.processServiceUpdates(services)
	}

	return nil
}

func (context *contextImpl) processServiceUpdates(services []*edge.Service) {
	idMap := make(map[string]*edge.Service)
	for _, s := range services {
		idMap[s.Id] = s
	}

	// process Deletes
	var deletes []string
	context.services.Range(func(key, value interface{}) bool {
		svc := value.(*edge.Service)
		k := key.(string)
		if _, found := idMap[svc.Id]; !found {
			deletes = append(deletes, k)
			if context.options.OnServiceUpdate != nil {
				context.options.OnServiceUpdate(config.ServiceRemoved, svc)
			}
			context.deleteServiceSessions(svc.Id)
		}
		return true
	})

	for _, deletedKey := range deletes {
		context.services.Delete(deletedKey)
	}

	// Adds and Updates
	for _, s := range services {
		val, exists := context.services.LoadOrStore(s.Name, s)
		if context.options.OnServiceUpdate != nil {
			if !exists {
				context.options.OnServiceUpdate(config.ServiceAdded, val.(*edge.Service))
			} else {
				if !reflect.DeepEqual(val, s) {
					context.services.Store(s.Name, s) // replace
					context.options.OnServiceUpdate(config.ServiceChanged, s)
				}
			}
		}
	}
}

func (context *contextImpl) refreshSessions() {
	log := pfxlog.Logger()
	context.sessions.Range(func(key, value interface{}) bool {
		log.Debugf("refreshing session for %s", key)

		session := value.(*edge.Session)
		if _, err := context.refreshSession(session.Id); err != nil {
			log.WithError(err).Errorf("failed to refresh session for %s", key)
		}

		return true
	})
}

func (context *contextImpl) runSessionRefresh() {
	log := pfxlog.Logger()
	svcUpdateTick := time.NewTicker(context.options.RefreshInterval)
	for {
		sleep := context.apiSession.Expires.Sub(time.Now()) - (10 * time.Second)
		select {
		case <-time.After(sleep):
			log.Debugf("refreshing api session")
			req, err := http.NewRequest("GET", context.zitiUrl.ResolveReference(currSess).String(), nil)
			req.Header.Set(constants.ZitiSession, context.apiSession.Token)
			resp, err := context.clt.Do(req)
			if err != nil || resp.StatusCode != 200 {
				log.Errorf("failed to get current session %+v, trying to login again", err)
				err = context.Authenticate()
				if err != nil {
					log.Fatalf("failed to login again")
					return
				}
			} else {
				apiSessionResp := &edge.ApiSession{}
				_, err = edge.ApiResponseDecode(apiSessionResp, resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					log.Fatalf("failed to parse current session")
					return
				}
				context.apiSession = apiSessionResp
				log.Debugf("session refreshed, new expiration[%s]", context.apiSession.Expires)
			}

		case <-svcUpdateTick.C:
			log.Debug("refreshing services")
			services, err := context.getServices()
			if err != nil {
				log.Errorf("failed to load service updates %+v", err)
			} else {
				context.processServiceUpdates(services)
				context.refreshSessions()
			}
		}
	}
}

func (context *contextImpl) EnsureAuthenticated(options edge.ConnOptions) error {
	operation := func() error {
		pfxlog.Logger().Infof("attempting to establish new api session")
		err := context.Authenticate()
		if err != nil && errors2.As(err, &AuthFailure{}) {
			return backoff.Permanent(err)
		}
		return err
	}
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = 10 * time.Second
	expBackoff.MaxElapsedTime = options.GetConnectTimeout()

	return backoff.Retry(operation, expBackoff)
}

func (context *contextImpl) Authenticate() error {
	logrus.Info("attempting to authenticate")
	context.services = sync.Map{}
	context.sessions = sync.Map{}

	req := new(bytes.Buffer)
	sdkInfo := sdkinfo.GetSdkInfo()
	if len(context.config.ConfigTypes) > 0 {
		if sdkInfoMap, ok := sdkInfo.(map[string]interface{}); ok {
			sdkInfoMap["configTypes"] = context.config.ConfigTypes
		} else {
			return errors.Errorf("SdkInfo is no longer a map[string]interface{}. Cannot request configTypes!")
		}
	}
	if err := json.NewEncoder(req).Encode(sdkInfo); err != nil {
		return err
	}
	resp, err := context.clt.Post(context.zitiUrl.ResolveReference(authUrl).String(), "application/json", req)
	if err != nil {
		pfxlog.Logger().Errorf("failure to post auth %+v", err)
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(resp.Body)
		pfxlog.Logger().Errorf("failed to authenticate with Ziti controller, result status: %v, msg: %v", resp.StatusCode, msg)
		return AuthFailure{
			httpCode: resp.StatusCode,
			msg:      string(msg),
		}
	}

	apiSessionResp := edge.ApiSession{}

	_, err = edge.ApiResponseDecode(&apiSessionResp, resp.Body)
	if err != nil {
		return err
	}
	logrus.
		WithField("session", apiSessionResp.Id).
		Debugf("logged in as %s/%s", apiSessionResp.Identity.Name, apiSessionResp.Identity.Id)
	context.apiSession = &apiSessionResp

	return nil
}

func (context *contextImpl) Dial(serviceName string) (edge.ServiceConn, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}
	id, ok := context.getServiceId(serviceName)
	if !ok {
		return nil, errors.Errorf("service '%s' not found", serviceName)
	}

	var conn edge.ServiceConn
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		ns, err := context.GetSession(id)
		if err != nil {
			return nil, err
		}
		conn, err = context.dialSession(serviceName, ns)
		if err != nil && attempt == 0 {
			if strings.Contains(err.Error(), "closed") {
				context.deleteServiceSessions(id)
				continue
			}
		}
		return conn, err
	}
	return nil, errors.Errorf("unable to dial service '%s' (%v)", serviceName, err)
}

func (context *contextImpl) dialSession(service string, session *edge.Session) (edge.ServiceConn, error) {
	edgeConnFactory, err := context.getEdgeRouterConn(session, edge.DialConnOptions{})
	if err != nil {
		return nil, err
	}
	edgeConn := edgeConnFactory.NewConn(service)
	return edgeConn.Connect(session)
}

func (context *contextImpl) Listen(serviceName string) (edge.Listener, error) {
	return context.ListenWithOptions(serviceName, edge.DefaultListenOptions())
}

func (context *contextImpl) ListenWithOptions(serviceName string, options *edge.ListenOptions) (edge.Listener, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if id, ok, _ := context.GetServiceId(serviceName); ok {
		return context.listenSession(id, serviceName, options), nil
	}
	return nil, errors.Errorf("service '%s' not found in ZT", serviceName)
}

func (context *contextImpl) listenSession(serviceId, serviceName string, options *edge.ListenOptions) edge.Listener {
	listenerMgr := newListenerManager(serviceId, serviceName, context, options)
	return listenerMgr.listener
}

func (context *contextImpl) getEdgeRouterConn(session *edge.Session, options edge.ConnOptions) (edge.RouterConn, error) {
	logger := pfxlog.Logger().WithField("ns", session.Token)

	if len(session.EdgeRouters) == 0 {
		return nil, errors.New("no edge routers available")
	}

	ch := make(chan *edgeRouterConnResult)

	for _, edgeRouter := range session.EdgeRouters {
		for _, routerUrl := range edgeRouter.Urls {
			go context.connectEdgeRouter(edgeRouter.Name, routerUrl, ch)
		}
	}

	timeout := time.After(options.GetConnectTimeout())
	for {
		select {
		case f := <-ch:
			if f.routerConnection != nil {
				logger.Debugf("using edgeRouter[%s]", f.routerConnection.Key())
				return f.routerConnection, nil
			}
		case <-timeout:
			return nil, errors.New("no edge routers connected in time")
		}
	}
}

func (context *contextImpl) connectEdgeRouter(routerName, ingressUrl string, ret chan *edgeRouterConnResult) {
	logger := pfxlog.Logger()

	if edgeConn, found := context.routerConnections.Get(ingressUrl); found {
		ret <- &edgeRouterConnResult{routerUrl: ingressUrl, routerConnection: edgeConn.(edge.RouterConn)}
		return
	}

	ingAddr, err := transport.ParseAddress(ingressUrl)
	if err != nil {
		logger.WithError(err).Errorf("failed to parse url[%s]", ingressUrl)
		ret <- &edgeRouterConnResult{routerUrl: ingressUrl, err: err}
		return
	}

	id := context.id
	dialer := channel2.NewClassicDialer(identity.NewIdentity(id), ingAddr, map[int32][]byte{
		edge.SessionTokenHeader: []byte(context.apiSession.Token),
	})

	ch, err := channel2.NewChannel("ziti-sdk", dialer, nil)
	if err != nil {
		logger.Error(err)
		select {
		case ret <- &edgeRouterConnResult{routerUrl: ingressUrl, err: err}:
		default:
		}
		return
	}

	edgeConn := impl.NewEdgeConnFactory(routerName, ingressUrl, ch, context)
	logger.Debugf("connected to %s", ingressUrl)

	useConn := context.routerConnections.Upsert(ingressUrl, edgeConn,
		func(exist bool, oldV interface{}, newV interface{}) interface{} {
			if exist { // use the routerConnection already in the map, close new one
				go func() {
					if err := newV.(edge.RouterConn).Close(); err != nil {
						pfxlog.Logger().Errorf("unable to close router connection (%v)", err)
					}
				}()
				return oldV
			}
			go metrics.ProbeLatency(ch, context.metrics.Histogram("latency."+ingressUrl), LatencyCheckInterval)
			return newV
		})

	select {
	case ret <- &edgeRouterConnResult{routerUrl: ingressUrl, routerConnection: useConn.(edge.RouterConn)}:
	default:
	}
}

func (context *contextImpl) GetServiceId(name string) (string, bool, error) {
	if err := context.initialize(); err != nil {
		return "", false, errors.Errorf("failed to initialize context: (%v)", err)
	}

	id, found := context.getServiceId(name)
	return id, found, nil
}

func (context *contextImpl) GetService(name string) (*edge.Service, bool) {
	s, found := context.services.Load(name)
	return s.(*edge.Service), found
}

func (context *contextImpl) getServiceId(name string) (string, bool) {
	if s, found := context.GetService(name); found {
		return s.Id, true
	}

	return "", false
}

func (context *contextImpl) GetServices() ([]edge.Service, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	var res []edge.Service
	context.services.Range(func(key, value interface{}) bool {
		svc := value.(*edge.Service)
		res = append(res, *svc)
		return true
	})
	return res, nil
}

func (context *contextImpl) getServices() ([]*edge.Service, error) {
	servReq, _ := http.NewRequest("GET", context.zitiUrl.ResolveReference(servicesUrl).String(), nil)

	if context.apiSession.Token == "" {
		return nil, errors.New("api session token is empty")
	} else {
		pfxlog.Logger().Debugf("using api session token %v", context.apiSession.Token)
	}
	servReq.Header.Set(constants.ZitiSession, context.apiSession.Token)
	pgOffset := 0
	pgLimit := 100

	var services []*edge.Service
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

		s := &[]*edge.Service{}
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

		if services == nil {
			services = make([]*edge.Service, 0, meta.Pagination.TotalCount)
		}

		for _, svc := range *s {
			services = append(services, svc)
		}

		pgOffset += pgLimit
		if pgOffset >= meta.Pagination.TotalCount {
			break
		}
	}

	return services, nil
}

func (context *contextImpl) GetSession(id string) (*edge.Session, error) {
	return context.createSession(id, edge.SessionDial)
}

func (context *contextImpl) GetBindSession(id string) (*edge.Session, error) {
	return context.createSession(id, edge.SessionBind)
}

func (context *contextImpl) createSession(id string, sessionType edge.SessionType) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}
	sessionKey := fmt.Sprintf("%s:%s", id, sessionType)
	val, ok := context.sessions.Load(sessionKey)
	if ok {
		return val.(*edge.Session), nil
	}

	body := fmt.Sprintf(`{"serviceId":"%s", "type": "%s"}`, id, sessionType)
	reqBody := bytes.NewBufferString(body)

	fullSessionUrl := context.zitiUrl.ResolveReference(sessionUrl).String()
	pfxlog.Logger().Debugf("requesting session from %v", fullSessionUrl)
	req, _ := http.NewRequest("POST", fullSessionUrl, reqBody)
	req.Header.Set(constants.ZitiSession, context.apiSession.Token)
	req.Header.Set("content-type", "application/json")

	logrus.WithField("service_id", id).Debug("requesting session")
	resp, err := context.clt.Do(req)

	if err != nil {
		return nil, err
	}
	return context.toSession("create", resp, 201)
}

func (context *contextImpl) refreshSession(id string) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	sessionLookupUrl, _ := url.Parse(fmt.Sprintf("/sessions/%v", id))
	sessionLookupUrlStr := context.zitiUrl.ResolveReference(sessionLookupUrl).String()
	pfxlog.Logger().Debugf("requesting session from %v", sessionLookupUrlStr)
	req, _ := http.NewRequest(http.MethodGet, sessionLookupUrlStr, nil)
	req.Header.Set(constants.ZitiSession, context.apiSession.Token)
	req.Header.Set("content-type", "application/json")

	logrus.WithField("sessionId", id).Debug("requesting session")
	resp, err := context.clt.Do(req)

	if err != nil {
		return nil, err
	}
	return context.toSession("refresh", resp, 200)
}

func (context *contextImpl) toSession(op string, resp *http.Response, expectedStatus int) (*edge.Session, error) {
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != expectedStatus {
		respBody, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, NotAuthorized
		}
		if resp.StatusCode == http.StatusBadRequest {
			return nil, NotAccessible{
				httpCode: resp.StatusCode,
				msg:      string(respBody),
			}
		}
		return nil, errors.Errorf("failed to %v session: %s\n%s", op, resp.Status, string(respBody))
	}

	session := new(edge.Session)
	_, err := edge.ApiResponseDecode(session, resp.Body)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("failed to decode session response")
		return nil, err
	}

	sessionKey := fmt.Sprintf("%s:%s", session.Service.Id, session.Type)

	if op == "create" {
		context.sessions.Store(sessionKey, session)
	} else if op == "refresh" {
		// N.B.: refreshed sessions do not contain token so update stored session object with updated edgeRouters
		val, exists := context.sessions.LoadOrStore(sessionKey, session)
		if exists {
			existingSession := val.(*edge.Session)
			existingSession.EdgeRouters = session.EdgeRouters
		}
	}

	return session, nil
}

func (context *contextImpl) deleteServiceSessions(svcId string) {
	context.sessions.Delete(fmt.Sprintf("%s:%s", svcId, edge.SessionBind))
	context.sessions.Delete(fmt.Sprintf("%s:%s", svcId, edge.SessionDial))
}

func (context *contextImpl) Close() {
	logger := pfxlog.Logger()

	// remove any closed connections
	for entry := range context.routerConnections.IterBuffered() {
		key, val := entry.Key, entry.Val.(edge.RouterConn)
		if !val.IsClosed() {
			if err := val.Close(); err != nil {
				logger.WithError(err).Error("error while closing connection")
			}
		}
		context.routerConnections.Remove(key)
	}
}

func (context *contextImpl) Metrics() metrics.Registry {
	_ = context.initialize()
	return context.metrics
}

func newListenerManager(serviceId, serviceName string, context *contextImpl, options *edge.ListenOptions) *listenerManager {
	now := time.Now()
	listenerMgr := &listenerManager{
		serviceId:         serviceId,
		context:           context,
		options:           options,
		routerConnections: map[string]edge.RouterConn{},
		connects:          map[string]time.Time{},
		listener:          impl.NewMultiListener(serviceName),
		connectChan:       make(chan *edgeRouterConnResult, 3),
		eventChan:         make(chan listenerEvent),
		disconnectedTime:  &now,
	}

	go listenerMgr.run()

	return listenerMgr
}

type listenerManager struct {
	serviceId          string
	context            *contextImpl
	session            *edge.Session
	options            *edge.ListenOptions
	routerConnections  map[string]edge.RouterConn
	connects           map[string]time.Time
	listener           impl.MultiListener
	connectChan        chan *edgeRouterConnResult
	eventChan          chan listenerEvent
	sessionRefreshTime time.Time
	disconnectedTime   *time.Time
}

func (mgr *listenerManager) run() {
	mgr.createSessionWithBackoff()
	mgr.makeMoreListeners()

	ticker := time.NewTicker(250 * time.Millisecond)
	refreshTicker := time.NewTicker(30 * time.Second)

	defer ticker.Stop()
	defer refreshTicker.Stop()

	for !mgr.listener.IsClosed() {
		select {
		case routerConnectionResult := <-mgr.connectChan:
			mgr.handleRouterConnectResult(routerConnectionResult)
		case event := <-mgr.eventChan:
			event.handle(mgr)
		case <-refreshTicker.C:
			mgr.refreshSession()
		case <-ticker.C:
			mgr.makeMoreListeners()
		}
	}
}

func (mgr *listenerManager) handleRouterConnectResult(result *edgeRouterConnResult) {
	delete(mgr.connects, result.routerUrl)
	routerConnection := result.routerConnection
	if routerConnection == nil {
		return
	}

	if len(mgr.routerConnections) < mgr.options.MaxConnections {
		if _, ok := mgr.routerConnections[routerConnection.GetRouterName()]; !ok {
			mgr.routerConnections[routerConnection.GetRouterName()] = routerConnection
			go mgr.createListener(routerConnection, mgr.session)
		}
	} else {
		pfxlog.Logger().Debugf("ignoring connection to %v, already have max connections %v", result.routerUrl, len(mgr.routerConnections))
	}
}

func (mgr *listenerManager) createListener(routerConnection edge.RouterConn, session *edge.Session) {
	logger := pfxlog.Logger()
	serviceName := mgr.listener.GetServiceName()
	edgeConn := routerConnection.NewConn(serviceName)
	listener, err := edgeConn.Listen(session, serviceName, mgr.options)
	if err == nil {
		mgr.listener.AddListener(listener, func() {
			mgr.eventChan <- &routerConnectionListenFailedEvent{
				router: routerConnection.GetRouterName(),
			}
		})
		mgr.eventChan <- listenSuccessEvent{}
	} else {
		logger.Errorf("creating listener failed: %v", err)
		if err := edgeConn.Close(); err != nil {
			pfxlog.Logger().Errorf("failed to close edgeConn %v for service '%v' (%v)", edgeConn.Id(), serviceName, err)
		}
		mgr.eventChan <- &routerConnectionListenFailedEvent{router: routerConnection.GetRouterName()}
	}
}

func (mgr *listenerManager) makeMoreListeners() {
	if mgr.listener.IsClosed() {
		return
	}

	// If we don't have any connections and there are no available edge routers, refresh the session more often
	if len(mgr.session.EdgeRouters) == 0 && len(mgr.routerConnections) == 0 {
		now := time.Now()
		if mgr.disconnectedTime.Add(mgr.options.ConnectTimeout).Before(now) {
			pfxlog.Logger().Warn("disconnected for longer than configured connect timeout. closing")
			err := errors.New("disconnected for longer than connect timeout. closing")
			mgr.listener.CloseWithError(err)
			return
		}

		if mgr.sessionRefreshTime.Add(time.Second).Before(now) {
			pfxlog.Logger().Warnf("no edge routers available, polling more frequently")
			mgr.refreshSession()
		}
	}

	if mgr.listener.IsClosed() || len(mgr.routerConnections) >= mgr.options.MaxConnections || len(mgr.session.EdgeRouters) <= len(mgr.routerConnections) {
		return
	}

	for _, edgeRouter := range mgr.session.EdgeRouters {
		if _, ok := mgr.routerConnections[edgeRouter.Name]; ok {
			// already connected to this router
			continue
		}

		for _, routerUrl := range edgeRouter.Urls {
			if _, ok := mgr.connects[routerUrl]; ok {
				// this url already has a connect in progress
				continue
			}

			mgr.connects[routerUrl] = time.Now()
			go mgr.context.connectEdgeRouter(edgeRouter.Name, routerUrl, mgr.connectChan)
		}
	}
}

func (mgr *listenerManager) refreshSession() {
	session, err := mgr.context.refreshSession(mgr.session.Id)
	if err != nil {
		if errors2.Is(err, NotAuthorized) {
			pfxlog.Logger().Debugf("failure refreshing bind session for service %v (%v)", mgr.listener.GetServiceName(), err)
			if err := mgr.context.EnsureAuthenticated(mgr.options); err != nil {
				err := fmt.Errorf("unable to establish API session (%w)", err)
				if len(mgr.routerConnections) == 0 {
					mgr.listener.CloseWithError(err)
				}
				return
			}
		}

		session, err = mgr.context.refreshSession(mgr.session.Id)
		if err != nil {
			if errors2.Is(err, NotAuthorized) {
				pfxlog.Logger().Errorf(
					"failure refreshing bind session even after re-authenticating api session. service %v (%v)",
					mgr.listener.GetServiceName(), err)
				if len(mgr.routerConnections) == 0 {
					mgr.listener.CloseWithError(err)
				}
				return
			}

			pfxlog.Logger().Errorf("failed to to refresh session %v: (%v)", mgr.session.Id, err)

			// try to create new session
			mgr.createSessionWithBackoff()
		}
	}

	if session != nil {
		// token only returned on created, so we have to backfill it on lookups
		session.Token = mgr.session.Token
		mgr.session = session
		mgr.sessionRefreshTime = time.Now()
	}
}

func (mgr *listenerManager) createSessionWithBackoff() {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 50 * time.Millisecond
	expBackoff.MaxInterval = 10 * time.Second
	expBackoff.MaxElapsedTime = mgr.options.GetConnectTimeout()

	_ = backoff.Retry(mgr.createSession, expBackoff)
}

func (mgr *listenerManager) createSession() error {
	logger := pfxlog.Logger()
	logger.Debugf("establishing bind session to service %v", mgr.listener.GetServiceName())
	session, err := mgr.context.GetBindSession(mgr.serviceId)
	if err != nil {
		logger.Warnf("failure creating bind session to service %v (%v)", mgr.listener.GetServiceName(), err)
		if errors2.Is(err, NotAuthorized) {
			if err := mgr.context.EnsureAuthenticated(mgr.options); err != nil {
				err := fmt.Errorf("unable to establish API session (%w)", err)
				if len(mgr.routerConnections) == 0 {
					mgr.listener.CloseWithError(err)
				}
				return backoff.Permanent(err)
			}
		} else if errors2.As(err, &NotAccessible{}) {
			logger.Warnf("session create failure not recoverable, not retrying")
			if len(mgr.routerConnections) == 0 {
				mgr.listener.CloseWithError(err)
			}
			return backoff.Permanent(err)
		}
		return err
	}
	logger.Debugf("successfully created bind session to service %v", mgr.listener.GetServiceName())
	mgr.session = session
	mgr.sessionRefreshTime = time.Now()
	return nil
}

type listenerEvent interface {
	handle(mgr *listenerManager)
}

type routerConnectionListenFailedEvent struct {
	router string
}

func (event *routerConnectionListenFailedEvent) handle(mgr *listenerManager) {
	pfxlog.Logger().Warnf("listener connection failed")
	delete(mgr.routerConnections, event.router)
	now := time.Now()
	if len(mgr.routerConnections) == 0 {
		mgr.disconnectedTime = &now
	}
	mgr.refreshSession()
	mgr.makeMoreListeners()
}

type edgeRouterConnResult struct {
	routerUrl        string
	routerConnection edge.RouterConn
	err              error
}

type listenSuccessEvent struct{}

func (event listenSuccessEvent) handle(mgr *listenerManager) {
	mgr.disconnectedTime = nil
}
