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
	"crypto/tls"
	errors2 "errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/transport"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/api"
	"github.com/openziti/sdk-golang/ziti/edge/impl"
	"github.com/openziti/sdk-golang/ziti/sdkinfo"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/url"
	"os"
	"reflect"
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

type contextImpl struct {
	config            *config.Config
	options           *config.Options
	initDone          sync.Once
	routerConnections cmap.ConcurrentMap

	id         identity.Identity
	zitiUrl    *url.URL
	tlsCtx     *tls.Config
	ctrlClt    api.Client
	apiSession *edge.ApiSession

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
	context.ctrlClt, err = api.NewClient(context.zitiUrl, id.ClientTLSConfig())

	if err = context.Authenticate(); err != nil {
		return err
	}
	go context.runSessionRefresh()

	metricsTags := map[string]string{
		"srcId": context.apiSession.Identity.Id,
	}

	context.metrics = metrics.NewRegistry(context.apiSession.Identity.Name, metricsTags)

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
	edgeRouters := make(map[string]string)
	context.sessions.Range(func(key, value interface{}) bool {
		log.Debugf("refreshing session for %s", key)

		session := value.(*edge.Session)
		if s, err := context.refreshSession(session.Id); err != nil {
			log.WithError(err).Errorf("failed to refresh session for %s", key)
		} else {
			for _, er := range s.EdgeRouters {
				for _, u := range er.Urls {
					edgeRouters[u] = er.Name
				}
			}
		}

		return true
	})

	for u, name := range edgeRouters {
		go context.connectEdgeRouter(name, u, nil)
	}

}

func (context *contextImpl) runSessionRefresh() {
	log := pfxlog.Logger()
	svcUpdateTick := time.NewTicker(context.options.RefreshInterval)
	expireTime := context.apiSession.Expires
	for {
		sleep := expireTime.Sub(time.Now()) - (10 * time.Second)
		select {
		case <-time.After(sleep):
			exp, err := context.ctrlClt.Refresh()
			if err != nil {
				log.Fatal(err)
			} else {
				expireTime = *exp
				log.Debugf("session refreshed, new expiration[%s]", expireTime)
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
		if err != nil && errors2.As(err, &api.AuthFailure{}) {
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
	logrus.Debug("attempting to authenticate")
	context.services = sync.Map{}
	context.sessions = sync.Map{}

	info, ok := sdkinfo.GetSdkInfo().(map[string]interface{})
	if !ok {
		return errors.Errorf("SdkInfo is no longer a map[string]interface{}. Cannot request configTypes!")
	}
	var err error
	context.apiSession, err = context.ctrlClt.Login(info, context.config.ConfigTypes)
	return err
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

	ch := make(chan *edgeRouterConnResult, 1)

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
	if err := context.initialize(); err != nil {
		return nil, false
	}
	if s, found := context.services.Load(name); !found {
		return nil, false
	} else {
		return s.(*edge.Service), true
	}
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
	return context.ctrlClt.GetServices()
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

	cache := sessionType == edge.SessionDial

	// Can't cache Bind sessions, as we use session tokens for routing. If there are multiple binds on a single
	// session routing information will get overwritten
	if cache {
		val, ok := context.sessions.Load(sessionKey)
		if ok {
			return val.(*edge.Session), nil
		}
	}

	session, err := context.ctrlClt.CreateSession(id, sessionType)

	if err != nil {
		return nil, err
	}
	return context.cacheSession("create", session)
}

func (context *contextImpl) refreshSession(id string) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	session, err := context.ctrlClt.RefreshSession(id)
	if err != nil {
		return nil, err
	}
	return context.cacheSession("refresh", session)
}

func (context *contextImpl) cacheSession(op string, session *edge.Session) (*edge.Session, error) {
	sessionKey := fmt.Sprintf("%s:%s", session.Service.Id, session.Type)

	if session.Type == edge.SessionDial {
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
		connectChan:       make(chan *edgeRouterConnResult, 3),
		eventChan:         make(chan listenerEvent),
		disconnectedTime:  &now,
	}

	listenerMgr.listener = impl.NewMultiListener(serviceName, listenerMgr.GetCurrentSession)

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
	start := time.Now()
	logger := pfxlog.Logger()
	serviceName := mgr.listener.GetServiceName()
	edgeConn := routerConnection.NewConn(serviceName)
	listener, err := edgeConn.Listen(session, serviceName, mgr.options)
	elapsed := time.Now().Sub(start)
	logger.Debugf("listener established to %v in %vms", routerConnection.Key(), elapsed.Milliseconds())
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
		if errors2.Is(err, api.NotAuthorized) {
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
			if errors2.Is(err, api.NotAuthorized) {
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
	start := time.Now()
	logger := pfxlog.Logger()
	logger.Debugf("establishing bind session to service %v", mgr.listener.GetServiceName())
	session, err := mgr.context.GetBindSession(mgr.serviceId)
	if err != nil {
		logger.Warnf("failure creating bind session to service %v (%v)", mgr.listener.GetServiceName(), err)
		if errors2.Is(err, api.NotAuthorized) {
			if err := mgr.context.EnsureAuthenticated(mgr.options); err != nil {
				err := fmt.Errorf("unable to establish API session (%w)", err)
				if len(mgr.routerConnections) == 0 {
					mgr.listener.CloseWithError(err)
				}
				return backoff.Permanent(err)
			}
		} else if errors2.As(err, &api.NotAccessible{}) {
			logger.Warnf("session create failure not recoverable, not retrying")
			if len(mgr.routerConnections) == 0 {
				mgr.listener.CloseWithError(err)
			}
			return backoff.Permanent(err)
		}
		return err
	}
	elapsed := time.Now().Sub(start)
	logger.Debugf("successfully created bind session to service %v in %vms", mgr.listener.GetServiceName(), elapsed.Milliseconds())
	mgr.session = session
	mgr.sessionRefreshTime = time.Now()
	return nil
}

func (mgr *listenerManager) GetCurrentSession() *edge.Session {
	if mgr.listener.IsClosed() {
		return nil
	}
	event := &getSessionEvent{
		doneC: make(chan struct{}),
	}
	timeout := time.After(5 * time.Second)

	select {
	case mgr.eventChan <- event:
	case <-timeout:
		return nil
	}

	select {
	case <-event.doneC:
		return event.session
	case <-timeout:
	}
	return nil
}

type listenerEvent interface {
	handle(mgr *listenerManager)
}

type routerConnectionListenFailedEvent struct {
	router string
}

func (event *routerConnectionListenFailedEvent) handle(mgr *listenerManager) {
	pfxlog.Logger().Infof("child listener connection closed. parent listener closed: %v", mgr.listener.IsClosed())
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

type getSessionEvent struct {
	session *edge.Session
	doneC   chan struct{}
}

func (event *getSessionEvent) handle(mgr *listenerManager) {
	defer close(event.doneC)
	event.session = mgr.session
}
