/*
	Copyright 2019 NetFoundry Inc.

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

package network

import (
	"fmt"
	"math"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/concurrenz"
	"github.com/openziti/foundation/v2/goroutines"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/pkg/errors"
)

type baseListener struct {
	service     *rest_model.ServiceDetail
	acceptC     chan edge.Conn
	closeNotify chan struct{}
	err         concurrenz.AtomicValue[error]
	closed      atomic.Bool
}

func (listener *baseListener) Network() string {
	return "ziti"
}

func (listener *baseListener) String() string {
	return *listener.service.Name
}

func (listener *baseListener) Addr() net.Addr {
	return listener
}

func (listener *baseListener) IsClosed() bool {
	return listener.closed.Load()
}

func (listener *baseListener) Accept() (net.Conn, error) {
	conn, err := listener.AcceptEdge()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (listener *baseListener) AcceptEdge() (edge.Conn, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for !listener.closed.Load() {
		select {
		case conn, ok := <-listener.acceptC:
			if ok && conn != nil {
				return conn, nil
			}
			listener.closed.Store(true)
		case <-ticker.C:
		}
	}

	if err := listener.err.Load(); err != nil {
		return nil, fmt.Errorf("listener is closed (%w)", err)
	}

	return nil, errors.New("listener is closed")
}

type MultiListener interface {
	edge.Listener
	edge.ListenerHost
	// AddListener registers an established child listener
	AddListener(listener edge.RouterHostConn)
	NotifyOfChildError(err error)
	GetServiceName() string
	GetService() *rest_model.ServiceDetail
	CloseWithError(err error)
	GetEstablishedCount() uint
	// HasListenerForRouter returns true if there is an active listener connected to the named router.
	HasListenerForRouter(routerName string) bool
	// GetListenerCount returns the number of active child listeners.
	GetListenerCount() int
}

func NewMultiListener(service *rest_model.ServiceDetail, queueSize int, getSessionF func() *rest_model.SessionDetail) MultiListener {
	if queueSize < 1 {
		queueSize = 10
	}
	ml := &multiListener{
		baseListener: baseListener{
			service: service,
			// Buffer matches pool size so a worker can hand off and pick up
			// the next dial without blocking on Accept().
			acceptC:     make(chan edge.Conn, queueSize),
			closeNotify: make(chan struct{}),
		},
		listeners:   map[*edgeHostConn]struct{}{},
		getSessionF: getSessionF,
	}
	pool, err := goroutines.NewPool(goroutines.PoolConfig{
		// QueueSize 1 means "essentially no waiting room": if all workers are
		// busy and the next dial can't be picked up immediately, fail fast and
		// let the router try another terminator.
		QueueSize:  1,
		MinWorkers: 0,
		MaxWorkers: uint32(queueSize),
		IdleTime:   30 * time.Second,
		PanicHandler: func(err interface{}) {
			pfxlog.Logger().
				WithField("serviceName", *service.Name).
				Errorf("panic in dial worker: %v", err)
		},
	})
	if err != nil {
		// PoolConfig.Validate only fails on misconfiguration we control here;
		// log and continue with a nil pool which is treated as "always full".
		pfxlog.Logger().WithError(err).Error("failed to create dial worker pool")
	}
	ml.dialPool = pool
	return ml
}

type multiListener struct {
	baseListener
	listeners            map[*edgeHostConn]struct{}
	listenerLock         sync.Mutex
	getSessionF          func() *rest_model.SessionDetail
	listenerEventHandler atomic.Value
	errorEventHandler    atomic.Value
	dialPool             goroutines.Pool
}

func (self *multiListener) QueueDial(work func()) error {
	if self.dialPool == nil {
		return goroutines.PoolStoppedError
	}
	return self.dialPool.QueueOrError(work)
}

// AcceptConn delivers an established conn to the application accept queue.
// Returns false when the multi-listener has been closed and the conn could
// not be delivered.
func (self *multiListener) AcceptConn(c edge.Conn) bool {
	select {
	case self.acceptC <- c:
		return true
	case <-self.closeNotify:
		return false
	}
}

// NotifyRouterConnClosed is invoked exactly once when a child listener
// closes. Removes the child from the listener set and fires the
// connection-change notification. Safe to call from edgeHostConn.close()
// because multi-listener Close spawns child closes in goroutines rather than
// calling them inline while holding listenerLock.
func (self *multiListener) NotifyRouterConnClosed(child edge.RouterHostConn) {
	listener, ok := child.(*edgeHostConn)
	if !ok {
		return
	}
	self.listenerLock.Lock()
	delete(self.listeners, listener)
	self.notifyOfConnectionChange()
	self.listenerLock.Unlock()
}

func (self *multiListener) Id() uint32 {
	return math.MaxUint32
}

func (self *multiListener) GetEstablishedCount() uint {
	var count uint
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()
	for v := range self.listeners {
		if v.established.Load() {
			count++
		}
	}
	return count
}

func (self *multiListener) HasListenerForRouter(routerName string) bool {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()
	for v := range self.listeners {
		if v.routerInfo.Name == routerName {
			return true
		}
	}
	return false
}

func (self *multiListener) GetListenerCount() int {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()
	return len(self.listeners)
}

func (self *multiListener) SetConnectionChangeHandler(handler func([]edge.RouterHostConn)) {
	self.listenerEventHandler.Store(handler)

	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()
	self.notifyOfConnectionChange()
}

func (self *multiListener) GetConnectionChangeHandler() func([]edge.RouterHostConn) {
	val := self.listenerEventHandler.Load()
	if val == nil {
		return nil
	}
	return val.(func([]edge.RouterHostConn))
}

func (self *multiListener) SetErrorEventHandler(handler func(error)) {
	self.errorEventHandler.Store(handler)
}

func (self *multiListener) GetErrorEventHandler() func(error) {
	val := self.errorEventHandler.Load()
	if val == nil {
		return nil
	}
	return val.(func(error))
}

func (self *multiListener) NotifyOfChildError(err error) {
	pfxlog.Logger().Infof("notify error handler of error: %v", err)
	if handler := self.GetErrorEventHandler(); handler != nil {
		handler(err)
	}
}

func (self *multiListener) notifyOfConnectionChange() {
	if handler := self.GetConnectionChangeHandler(); handler != nil {
		var list []edge.RouterHostConn
		for k := range self.listeners {
			list = append(list, k)
		}
		go handler(list)
	}
}

func (self *multiListener) GetCurrentSession() *rest_model.SessionDetail {
	return self.getSessionF()
}

func (self *multiListener) UpdateCost(cost uint16) error {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()

	var resultErrors []error
	for child := range self.listeners {
		if err := child.UpdateCost(cost); err != nil {
			resultErrors = append(resultErrors, err)
		}
	}
	return self.condenseErrors(resultErrors)
}

func (self *multiListener) UpdatePrecedence(precedence edge.Precedence) error {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()

	var resultErrors []error
	for child := range self.listeners {
		if err := child.UpdatePrecedence(precedence); err != nil {
			resultErrors = append(resultErrors, err)
		}
	}
	return self.condenseErrors(resultErrors)
}

func (self *multiListener) UpdateCostAndPrecedence(cost uint16, precedence edge.Precedence) error {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()

	var resultErrors []error
	for child := range self.listeners {
		if err := child.UpdateCostAndPrecedence(cost, precedence); err != nil {
			resultErrors = append(resultErrors, err)
		}
	}
	return self.condenseErrors(resultErrors)
}

func (self *multiListener) SendHealthEvent(pass bool) error {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()

	// only send to first child, otherwise we get duplicate event reporting
	for child := range self.listeners {
		return child.SendHealthEvent(pass)
	}
	return nil
}

func (self *multiListener) condenseErrors(errors []error) error {
	if len(errors) == 0 {
		return nil
	}
	if len(errors) == 1 {
		return errors[0]
	}
	return MultipleErrors(errors)
}

func (self *multiListener) GetServiceName() string {
	return *self.service.Name
}

func (self *multiListener) GetService() *rest_model.ServiceDetail {
	return self.service
}

// AddListener registers an established edge.RouterHostConn as a child of this
// multiListener. The listener's host wiring (NotifyRouterConnClosed) must
// already be set on the underlying edgeHostConn (via edge.ListenOptions.Host
// at routerConn.Listen time).
func (self *multiListener) AddListener(netListener edge.RouterHostConn) {
	listener, ok := netListener.(*edgeHostConn)
	if !ok {
		pfxlog.Logger().Errorf("multi-listener expects only listeners created by the SDK, not %v", reflect.TypeOf(self))
		return
	}

	self.listenerLock.Lock()
	// Check closed under the lock: Close() takes listenerLock and sets
	// self.listeners = nil, so writing without this guard would race and
	// panic if Close ran between an unlocked check and the lock acquire.
	if self.closed.Load() {
		self.listenerLock.Unlock()
		if err := listener.Close(); err != nil {
			pfxlog.Logger().WithError(err).Error("error closing listener added after multi-listener was closed")
		}
		return
	}
	self.listeners[listener] = struct{}{}
	self.notifyOfConnectionChange()
	self.listenerLock.Unlock()

	time.AfterFunc(time.Minute, func() {
		if !listener.established.Load() {
			pfxlog.Logger().
				WithField("connId", listener.Id()).
				WithField("routerName", listener.routerInfo.Name).
				WithField("serviceName", *listener.service.Name).
				Warn("listener was not established in time, closing")
			if err := listener.Close(); err != nil {
				pfxlog.Logger().Errorf("failure closing edge listener: (%v)", err)
			}
		}
	})
}

func (self *multiListener) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		// Signal closeNotify before taking listenerLock so any pool worker
		// blocked in AcceptConn unblocks and bails before we tear down state.
		close(self.closeNotify)

		self.listenerLock.Lock()
		defer self.listenerLock.Unlock()

		// Spawn each child close in its own goroutine. The child's close path
		// calls back into NotifyRouterConnClosed, which re-acquires listenerLock
		// to remove itself from self.listeners; doing those calls inline here
		// while we hold listenerLock would deadlock.
		for child := range self.listeners {
			go func(c *edgeHostConn) {
				if err := c.Close(); err != nil {
					pfxlog.Logger().WithError(err).Error("error closing child listener")
				}
			}(child)
		}

		self.listeners = nil

		if self.dialPool != nil {
			self.dialPool.Shutdown()
		}

		select {
		case self.acceptC <- nil:
		default:
			// If the queue is full, bail out, we're just popping a nil on the
			// accept queue to let it return from accept more quickly
		}
	}

	return nil
}

func (self *multiListener) CloseWithError(err error) {
	self.err.Store(err)
	if closeErr := self.Close(); closeErr != nil {
		pfxlog.Logger().WithError(err).Error("error closing edge listener")
	}
}

type MultipleErrors []error

func (e MultipleErrors) Error() string {
	if len(e) == 0 {
		return "no errors occurred"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	buf := strings.Builder{}
	buf.WriteString("multiple errors occurred")
	for idx, err := range e {
		_, _ = fmt.Fprintf(&buf, " %v: %v", idx, err)
	}
	return buf.String()
}
