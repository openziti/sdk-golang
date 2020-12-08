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
	errors2 "errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/common"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/transport"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/api"
	"github.com/openziti/sdk-golang/ziti/edge/impl"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	"github.com/openziti/sdk-golang/ziti/sdkinfo"
	"github.com/openziti/sdk-golang/ziti/signing"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/pkg/errors"
	metrics2 "github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"math"
	"reflect"
	"sync"
	"time"
)

const (
	LatencyCheckInterval = 30 * time.Second
)

type Context interface {
	Authenticate() error
	Dial(serviceName string) (edge.ServiceConn, error)
	DialWithOptions(serviceName string, options *DialOptions) (edge.ServiceConn, error)
	Listen(serviceName string) (edge.Listener, error)
	ListenWithOptions(serviceName string, options *ListenOptions) (edge.Listener, error)
	GetServiceId(serviceName string) (string, bool, error)
	GetServices() ([]edge.Service, error)
	GetService(serviceName string) (*edge.Service, bool)

	GetSession(id string) (*edge.Session, error)

	Metrics() metrics.Registry
	// Close closes any connections open to edge routers
	Close()
}

type DialOptions struct {
	ConnectTimeout time.Duration
	Identity       string
	AppData        []byte
}

func (d DialOptions) GetConnectTimeout() time.Duration {
	return d.ConnectTimeout
}

type Precedence byte

const (
	PrecedenceDefault  Precedence = 0
	PrecedenceRequired            = 1
	PrecedenceFailed              = 2
)

type ListenOptions struct {
	Cost                  uint16
	Precedence            Precedence
	ConnectTimeout        time.Duration
	MaxConnections        int
	Identity              string
	BindUsingEdgeIdentity bool
	ManualStart           bool
}

func DefaultListenOptions() *ListenOptions {
	return &ListenOptions{
		Cost:           0,
		Precedence:     PrecedenceDefault,
		ConnectTimeout: 5 * time.Second,
		MaxConnections: 3,
	}
}

type contextImpl struct {
	configTypes       []string
	options           *config.Options
	routerConnections cmap.ConcurrentMap

	ctrlClt api.Client

	services sync.Map // name -> Service
	sessions sync.Map // svcID:type -> Session

	metrics metrics.Registry

	firstAuthOnce sync.Once

	postureCache *posture.Cache
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

	result := &contextImpl{
		routerConnections: cmap.New(),
		configTypes:       cfg.ConfigTypes,
		options:           options,
	}

	result.ctrlClt = api.NewLazyClient(cfg, func(ctrlClient api.Client) error {
		result.postureCache = posture.NewCache(ctrlClient)
		return nil
	})

	return result
}

func (context *contextImpl) initialize() error {
	return context.ctrlClt.Initialize()
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

	serviceQueryMap := map[string]map[string]edge.PostureQuery{} //serviceId -> queryId -> query

	context.services.Range(func(serviceId, val interface{}) bool {
		if service, ok := val.(*edge.Service); ok {
			for _, querySets := range service.PostureQueries {
				for _, query := range querySets.PostureQueries {
					var queryMap map[string]edge.PostureQuery
					var ok bool
					if queryMap, ok = serviceQueryMap[service.Id]; !ok {
						queryMap = map[string]edge.PostureQuery{}
						serviceQueryMap[service.Id] = queryMap
					}
					queryMap[query.Id] = query
				}
			}
		}
		return true
	})

	context.postureCache.SetServiceQueryMap(serviceQueryMap)

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
	expireTime := context.ctrlClt.GetCurrentApiSession().Expires
	sleepDuration := expireTime.Sub(time.Now()) - (10 * time.Second)
	for {

		select {
		case <-time.After(sleepDuration):
			exp, err := context.ctrlClt.Refresh()
			if err != nil {
				log.Errorf("could not refresh apiSession: %v", err)

				sleepDuration = 5 * time.Second
			} else {
				expireTime = *exp
				sleepDuration = expireTime.Sub(time.Now()) - (10 * time.Second)
				log.Debugf("apiSession refreshed, new expiration[%s]", expireTime)
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
		pfxlog.Logger().Info("attempting to establish new api session")
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
	if err := context.initialize(); err != nil {
		return errors.Errorf("failed to initialize context: (%v)", err)
	}

	if context.ctrlClt.GetCurrentApiSession() != nil {
		logrus.Debug("previous apiSession detected, checking if valid")
		if _, err := context.ctrlClt.Refresh(); err == nil {
			logrus.Info("previous apiSession refreshed")
			return nil
		} else {
			logrus.WithError(err).Info("previous apiSession failed to refresh, attempting to authenticate")
		}
	}

	logrus.Debug("attempting to authenticate")
	context.services = sync.Map{}
	context.sessions = sync.Map{}

	info, ok := sdkinfo.GetSdkInfo().(map[string]interface{})
	if !ok {
		return errors.Errorf("SdkInfo is no longer a map[string]interface{}. Cannot request configTypes!")
	}
	var err error
	if _, err = context.ctrlClt.Login(info, context.configTypes); err != nil {
		return err
	}

	// router connections are establishing using the api token. If we re-authenticate we must re-establish connections
	context.routerConnections.IterCb(func(key string, v interface{}) {
		_ = v.(edge.RouterConn).Close()
	})

	context.routerConnections = cmap.New()

	var doOnceErr error
	context.firstAuthOnce.Do(func() {
		go context.runSessionRefresh()

		metricsTags := map[string]string{
			"srcId": context.ctrlClt.GetCurrentApiSession().Identity.Id,
		}

		context.metrics = metrics.NewRegistry(context.ctrlClt.GetCurrentApiSession().Identity.Name, metricsTags)

		// get services
		if services, err := context.getServices(); err != nil {
			doOnceErr = err
		} else {
			context.processServiceUpdates(services)
		}
	})

	return doOnceErr
}

func (context *contextImpl) Dial(serviceName string) (edge.ServiceConn, error) {
	defaultOptions := &DialOptions{ConnectTimeout: 5 * time.Second}
	return context.DialWithOptions(serviceName, defaultOptions)
}

func (context *contextImpl) DialWithOptions(serviceName string, options *DialOptions) (edge.ServiceConn, error) {
	edgeDialOptions := &edge.DialOptions{
		ConnectTimeout: options.ConnectTimeout,
		Identity:       options.Identity,
		AppData:        options.AppData,
	}
	if edgeDialOptions.GetConnectTimeout() == 0 {
		edgeDialOptions.ConnectTimeout = 15 * time.Second
	}
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	service, ok := context.GetService(serviceName)
	if !ok {
		return nil, errors.Errorf("service '%s' not found", serviceName)
	}

	context.postureCache.AddActiveService(service.Id)

	edgeDialOptions.CallerId = context.ctrlClt.GetCurrentApiSession().Identity.Name

	var conn edge.ServiceConn
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var session *edge.Session
		session, err = context.GetSession(service.Id)
		if err != nil {
			continue
		}
		pfxlog.Logger().Infof("connecting via session id [%s] token [%s]", session.Id, session.Token)
		conn, err = context.dialSession(service, session, edgeDialOptions)
		if err != nil {
			if _, refreshErr := context.refreshSession(session.Id); refreshErr != nil {
				context.deleteServiceSessions(service.Id)
				if _, err = context.createSessionWithBackoff(service, edge.SessionDial, options); err != nil {
					break
				}
			}
			continue
		}
		return conn, err
	}
	return nil, errors.Wrapf(err, "unable to dial service '%s'", serviceName)
}

func (context *contextImpl) dialSession(service *edge.Service, session *edge.Session, options *edge.DialOptions) (edge.ServiceConn, error) {
	edgeConnFactory, err := context.getEdgeRouterConn(session, options)
	if err != nil {
		return nil, err
	}
	edgeConn := edgeConnFactory.NewConn(service)
	return edgeConn.Connect(session, options)
}

func (context *contextImpl) ensureApiSession() error {
	if context.ctrlClt.GetCurrentApiSession() == nil {
		if err := context.Authenticate(); err != nil {
			return fmt.Errorf("no apiSession, authentication attempt failed: %v", err)
		}
	}
	return nil
}

func (context *contextImpl) Listen(serviceName string) (edge.Listener, error) {
	return context.ListenWithOptions(serviceName, DefaultListenOptions())
}

func (context *contextImpl) ListenWithOptions(serviceName string, options *ListenOptions) (edge.Listener, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	if s, ok := context.GetService(serviceName); ok {
		return context.listenSession(s, options), nil
	}
	return nil, errors.Errorf("service '%s' not found in ZT", serviceName)
}

func (context *contextImpl) listenSession(service *edge.Service, options *ListenOptions) edge.Listener {
	edgeListenOptions := &edge.ListenOptions{
		Cost:                  options.Cost,
		Precedence:            edge.Precedence(options.Precedence),
		ConnectTimeout:        options.ConnectTimeout,
		MaxConnections:        options.MaxConnections,
		Identity:              options.Identity,
		BindUsingEdgeIdentity: options.BindUsingEdgeIdentity,
		ManualStart:           options.ManualStart,
	}

	if edgeListenOptions.ConnectTimeout == 0 {
		edgeListenOptions.ConnectTimeout = time.Minute
	}

	if edgeListenOptions.MaxConnections < 1 {
		edgeListenOptions.MaxConnections = 1
	}

	listenerMgr := newListenerManager(service, context, edgeListenOptions)
	return listenerMgr.listener
}

func (context *contextImpl) getEdgeRouterConn(session *edge.Session, options edge.ConnOptions) (edge.RouterConn, error) {
	logger := pfxlog.Logger().WithField("ns", session.Token)

	if refreshedSession, err := context.refreshSession(session.Id); err != nil {
		if _, isNotFound := err.(api.NotFound); isNotFound {
			sessionKey := fmt.Sprintf("%s:%s", session.Service.Id, session.Type)
			context.sessions.Delete(sessionKey)
		}

		return nil, fmt.Errorf("no edge routers available, refresh errored: %v", err)
	} else {
		if len(refreshedSession.EdgeRouters) == 0 {
			return nil, errors.New("no edge routers available, refresh yielded no new edge routers")
		}

		session = refreshedSession
	}

	// go through connected routers first
	bestLatency := time.Duration(math.MaxInt64)
	var bestER edge.RouterConn
	var unconnected []edge.EdgeRouter
	for _, edgeRouter := range session.EdgeRouters {
		for _, routerUrl := range edgeRouter.Urls {
			if er, found := context.routerConnections.Get(routerUrl); found {
				h := context.metrics.Histogram("latency." + routerUrl).(metrics2.Histogram)
				if h.Mean() < float64(bestLatency) {
					bestLatency = time.Duration(int64(h.Mean()))
					bestER = er.(edge.RouterConn)
				}
			} else {
				unconnected = append(unconnected, edgeRouter)
			}
		}
	}

	var ch chan *edgeRouterConnResult
	if bestER == nil {
		ch = make(chan *edgeRouterConnResult, len(unconnected))
	}

	for _, edgeRouter := range unconnected {
		for _, routerUrl := range edgeRouter.Urls {
			go context.connectEdgeRouter(edgeRouter.Name, routerUrl, ch)
		}
	}

	if bestER != nil {
		logger.Debugf("selected router[%s@%s] for best latency(%d ms)",
			bestER.GetRouterName(), bestER.Key(), bestLatency.Milliseconds())
		return bestER, nil
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

	retF := func(res *edgeRouterConnResult) {
		select {
		case ret <- res:
		default:
		}
	}

	if edgeConn, found := context.routerConnections.Get(ingressUrl); found {
		conn := edgeConn.(edge.RouterConn)
		if !conn.IsClosed() {
			retF(&edgeRouterConnResult{routerUrl: ingressUrl, routerConnection: conn})
			return
		} else {
			context.routerConnections.Remove(ingressUrl)
		}
	}

	ingAddr, err := transport.ParseAddress(ingressUrl)
	if err != nil {
		logger.WithError(err).Errorf("failed to parse url[%s]", ingressUrl)
		retF(&edgeRouterConnResult{routerUrl: ingressUrl, err: err})
		return
	}

	pfxlog.Logger().Infof("connection to edge router using token %v", context.ctrlClt.GetCurrentApiSession().Token)
	dialer := channel2.NewClassicDialer(identity.NewIdentity(context.ctrlClt.GetIdentity()), ingAddr, map[int32][]byte{
		edge.SessionTokenHeader: []byte(context.ctrlClt.GetCurrentApiSession().Token),
	})

	start := time.Now().UnixNano()
	ch, err := channel2.NewChannel("ziti-sdk", dialer, nil)
	if err != nil {
		logger.Error(err)
		retF(&edgeRouterConnResult{routerUrl: ingressUrl, err: err})
		return
	}
	connectTime := time.Duration(time.Now().UnixNano() - start)
	logger.Debugf("routerConn[%s@%s] connected in %d ms", routerName, ingressUrl, connectTime.Milliseconds())

	if versionHeader, found := ch.Underlay().Headers()[channel2.HelloVersionHeader]; found {
		versionInfo, err := common.StdVersionEncDec.Decode(versionHeader)
		if err != nil {
			pfxlog.Logger().Errorf("could not parse hello version header: %v", err)
		} else {
			pfxlog.Logger().
				WithField("os", versionInfo.OS).
				WithField("arch", versionInfo.Arch).
				WithField("version", versionInfo.Version).
				WithField("revision", versionInfo.Revision).
				WithField("buildDate", versionInfo.BuildDate).
				Debug("connected to edge router")
		}
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
			h := context.metrics.Histogram("latency." + ingressUrl)
			h.Update(int64(connectTime))
			go metrics.ProbeLatency(ch, h, LatencyCheckInterval)
			return newV
		})

	retF(&edgeRouterConnResult{routerUrl: ingressUrl, routerConnection: useConn.(edge.RouterConn)})
}

func (context *contextImpl) GetServiceId(name string) (string, bool, error) {
	if err := context.initialize(); err != nil {
		return "", false, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return "", false, fmt.Errorf("failed to get service id: %v", err)
	}

	id, found := context.getServiceId(name)
	return id, found, nil
}

func (context *contextImpl) GetService(name string) (*edge.Service, bool) {
	if err := context.initialize(); err != nil {
		return nil, false
	}

	if err := context.ensureApiSession(); err != nil {
		pfxlog.Logger().Warnf("failed to get service: %v", err)
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

	if err := context.ensureApiSession(); err != nil {
		return nil, fmt.Errorf("failed to get services: %v", err)
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

func (context *contextImpl) GetSession(serviceId string) (*edge.Session, error) {
	return context.getOrCreateSession(serviceId, edge.SessionDial)
}

func (context *contextImpl) getOrCreateSession(serviceId string, sessionType edge.SessionType) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}
	sessionKey := fmt.Sprintf("%s:%s", serviceId, sessionType)

	cache := sessionType == edge.SessionDial

	// Can't cache Bind sessions, as we use session tokens for routing. If there are multiple binds on a single
	// session routing information will get overwritten
	if cache {
		val, ok := context.sessions.Load(sessionKey)
		if ok {
			return val.(*edge.Session), nil
		}
	}

	context.postureCache.AddActiveService(serviceId)
	session, err := context.ctrlClt.CreateSession(serviceId, sessionType)

	if err != nil {
		return nil, err
	}
	context.cacheSession("create", session)
	return session, nil
}

func (context *contextImpl) createSessionWithBackoff(service *edge.Service, sessionType edge.SessionType, options edge.ConnOptions) (*edge.Session, error) {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 50 * time.Millisecond
	expBackoff.MaxInterval = 10 * time.Second
	expBackoff.MaxElapsedTime = options.GetConnectTimeout()

	var session *edge.Session
	operation := func() error {
		s, err := context.createSession(service, sessionType, options)
		if err != nil {
			return err
		}
		session = s
		return nil
	}

	if session != nil {
		context.postureCache.AddActiveService(service.Id)
		context.cacheSession("create", session)
	}

	return session, backoff.Retry(operation, expBackoff)
}

func (context *contextImpl) createSession(service *edge.Service, sessionType edge.SessionType, options edge.ConnOptions) (*edge.Session, error) {
	start := time.Now()
	logger := pfxlog.Logger()
	logger.Debugf("establishing %v session to service %v", sessionType, service.Name)
	session, err := context.getOrCreateSession(service.Id, sessionType)
	if err != nil {
		logger.WithError(err).Warnf("failure creating %v session to service %v", sessionType, service.Name)
		if errors2.Is(err, api.NotAuthorized) {
			if err := context.Authenticate(); err != nil {
				if errors2.As(err, &api.AuthFailure{}) {
					return nil, backoff.Permanent(err)
				}
				return nil, err
			}
		} else if errors2.As(err, &api.NotAccessible{}) {
			logger.Warnf("session create failure not recoverable, not retrying")
			return nil, backoff.Permanent(err)
		}
		return nil, err
	}
	elapsed := time.Now().Sub(start)
	logger.Debugf("successfully created %v session to service %v in %vms", sessionType, service.Name, elapsed.Milliseconds())
	return session, nil
}

func (context *contextImpl) refreshSession(id string) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	session, err := context.ctrlClt.RefreshSession(id)
	if err != nil {
		return nil, err
	}
	context.cacheSession("refresh", session)
	return session, nil
}

func (context *contextImpl) cacheSession(op string, session *edge.Session) {
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

func newListenerManager(service *edge.Service, context *contextImpl, options *edge.ListenOptions) *listenerManager {
	now := time.Now()

	listenerMgr := &listenerManager{
		service:           service,
		context:           context,
		options:           options,
		routerConnections: map[string]edge.RouterConn{},
		connects:          map[string]time.Time{},
		connectChan:       make(chan *edgeRouterConnResult, 3),
		eventChan:         make(chan listenerEvent),
		disconnectedTime:  &now,
	}

	listenerMgr.listener = impl.NewMultiListener(service, listenerMgr.GetCurrentSession)

	go listenerMgr.run()

	return listenerMgr
}

type listenerManager struct {
	service            *edge.Service
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

	if mgr.options.BindUsingEdgeIdentity {
		mgr.options.Identity = mgr.context.ctrlClt.GetCurrentApiSession().Identity.Name
	}

	if mgr.options.Identity != "" {
		identitySecret, err := signing.AssertIdentityWithSecret(mgr.context.ctrlClt.GetIdentity().Cert().PrivateKey)
		if err != nil {
			pfxlog.Logger().Errorf("failed to sign identity: %v", err)
		} else {
			mgr.options.IdentitySecret = string(identitySecret)
		}
	}

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
	service := mgr.listener.GetService()
	edgeConn := routerConnection.NewConn(service)
	listener, err := edgeConn.Listen(session, service, mgr.options)
	elapsed := time.Now().Sub(start)
	if err == nil {
		logger.Debugf("listener established to %v in %vms", routerConnection.Key(), elapsed.Milliseconds())
		mgr.listener.AddListener(listener, func() {
			mgr.eventChan <- &routerConnectionListenFailedEvent{
				router: routerConnection.GetRouterName(),
			}
		})
		mgr.eventChan <- listenSuccessEvent{}
	} else {
		logger.Errorf("creating listener failed after %vms: %v", elapsed.Milliseconds(), err)
		mgr.listener.NotifyOfChildError(err)
		if err := edgeConn.Close(); err != nil {
			pfxlog.Logger().Errorf("failed to close edgeConn %v for service '%v' (%v)", edgeConn.Id(), service.Name, err)
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

	// token only returned on created, so if we refreshed the session (as opposed to creating a new one) we have to backfill it on lookups
	if session != nil {
		session.Token = mgr.session.Token
		mgr.session = session
		mgr.sessionRefreshTime = time.Now()
	}
}

func (mgr *listenerManager) createSessionWithBackoff() {
	session, err := mgr.context.createSessionWithBackoff(mgr.service, edge.SessionBind, mgr.options)
	if session != nil {
		mgr.session = session
		mgr.sessionRefreshTime = time.Now()
	} else {
		pfxlog.Logger().Errorf("failed to to refresh session %v: (%v)", mgr.session.Id, err)
	}
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
