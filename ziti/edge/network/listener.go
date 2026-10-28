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
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/pkg/errors"
)

type baseListener struct {
	service *rest_model.ServiceDetail
	acceptC chan edge.Conn
	err     concurrenz.AtomicValue[error]
	closed  atomic.Bool
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
	AddListener(listener edge.RouterHostConn, closeHandler func())
	NotifyOfChildError(err error)
	GetServiceName() string
	GetService() *rest_model.ServiceDetail
	CloseWithError(err error)
	GetEstablishedCount() uint
	// HasListenerForRouter returns true if there is an active listener connected to the named router.
	HasListenerForRouter(routerName string) bool
	// GetListenerCount returns the number of active child listeners.
	GetListenerCount() int
	// GetCostAndPrecedence returns the cost and precedence a new bind should carry: the values most
	// recently set through UpdateCost, UpdatePrecedence or UpdateCostAndPrecedence, or the initial ones.
	GetCostAndPrecedence() (uint16, edge.Precedence)
}

// NewMultiListener returns a MultiListener for service. cost and precedence are the initial values
// reported by GetCostAndPrecedence.
func NewMultiListener(service *rest_model.ServiceDetail, cost uint16, precedence edge.Precedence, getSessionF func() *rest_model.SessionDetail) MultiListener {
	return &multiListener{
		baseListener: baseListener{
			service: service,
			acceptC: make(chan edge.Conn),
		},
		listeners:   map[*edgeHostConn]struct{}{},
		getSessionF: getSessionF,
		cost:        cost,
		precedence:  precedence,
	}
}

type multiListener struct {
	baseListener
	listeners            map[*edgeHostConn]struct{}
	listenerLock         sync.Mutex
	getSessionF          func() *rest_model.SessionDetail
	listenerEventHandler atomic.Value
	errorEventHandler    atomic.Value

	// cost, precedence and updated are guarded by listenerLock.
	cost       uint16
	precedence edge.Precedence
	updated    bool
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

func (self *multiListener) GetCostAndPrecedence() (uint16, edge.Precedence) {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()
	return self.cost, self.precedence
}

func (self *multiListener) UpdateCost(cost uint16) error {
	return self.updateCostAndPrecedence(&cost, nil)
}

func (self *multiListener) UpdatePrecedence(precedence edge.Precedence) error {
	return self.updateCostAndPrecedence(nil, &precedence)
}

func (self *multiListener) UpdateCostAndPrecedence(cost uint16, precedence edge.Precedence) error {
	return self.updateCostAndPrecedence(&cost, &precedence)
}

// updateCostAndPrecedence records the non-nil values for future binds and sends them to every child
// whose bind the router has confirmed; reconcile covers the rest once they are confirmed. The returned
// error covers only the sends; the values are recorded regardless.
func (self *multiListener) updateCostAndPrecedence(cost *uint16, precedence *edge.Precedence) error {
	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()

	if cost != nil {
		self.cost = *cost
	}
	if precedence != nil {
		self.precedence = *precedence
	}
	self.updated = true

	var resultErrors []error
	for child := range self.listeners {
		// Before confirmation the controller may not have the terminator yet, and would reject the update.
		if !child.established.Load() {
			continue
		}
		if err := child.updateCostAndPrecedence(cost, precedence); err != nil {
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

func (self *multiListener) AddListener(netListener edge.RouterHostConn, closeHandler func()) {
	listener, ok := netListener.(*edgeHostConn)
	if !ok {
		pfxlog.Logger().Errorf("multi-listener expects only listeners created by the SDK, not %v", reflect.TypeOf(self))
		return
	}

	if self.closed.Load() {
		if err := listener.Close(); err != nil {
			pfxlog.Logger().WithError(err).Error("error closing listener added after multi-listener was closed")
		}
		return
	}

	self.listenerLock.Lock()
	defer self.listenerLock.Unlock()
	self.listeners[listener] = struct{}{}

	// Every confirmation is reconciled, not only one whose bind carried stale values: the router may have
	// handed the bind an existing terminator for its listener id, or re-created the terminator from the
	// bind's values. The confirmation may also have arrived before the handler was set.
	listener.confirmedHandler.Store(func() {
		self.listenerLock.Lock()
		defer self.listenerLock.Unlock()
		self.reconcile(listener)
	})
	if listener.established.Load() {
		self.reconcile(listener)
	}

	closer := func() {
		self.listenerLock.Lock()
		defer self.listenerLock.Unlock()
		delete(self.listeners, listener)

		self.notifyOfConnectionChange()
		go closeHandler()
	}

	self.notifyOfConnectionChange()

	go self.forward(listener, closer)
}

// reconcile sends the recorded cost and precedence to child if it is still a child and the values have
// been updated since the listener was created. The caller holds listenerLock.
func (self *multiListener) reconcile(child *edgeHostConn) {
	if !self.updated {
		return
	}
	if _, ok := self.listeners[child]; !ok {
		return
	}
	if err := child.UpdateCostAndPrecedence(self.cost, self.precedence); err != nil {
		pfxlog.Logger().WithField("connId", child.Id()).
			WithField("serviceName", child.serviceName).
			WithError(err).Error("failed to send cost and precedence to confirmed listener")
	}
}

func (self *multiListener) forward(edgeListener *edgeHostConn, closeHandler func()) {
	defer func() {
		if err := edgeListener.Close(); err != nil {
			pfxlog.Logger().Errorf("failure closing edge listener: (%v)", err)
		}
		closeHandler()
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	establishDeadline := time.Now().Add(time.Minute)

	for !self.closed.Load() && !edgeListener.flags.IsSet(hostConnClosedFlag) {
		select {
		case conn, ok := <-edgeListener.acceptC:
			if !ok || conn == nil {
				// closed, returning
				return
			}
			self.accept(conn, ticker)
		case <-ticker.C:
			// lets us check if the listener is closed, and exit if it has
			if !edgeListener.established.Load() && time.Now().After(establishDeadline) {
				pfxlog.Logger().
					WithField("connId", edgeListener.Id()).
					WithField("routerName", edgeListener.routerInfo.Name).
					WithField("serviceName", edgeListener.serviceName).
					Warn("listener was not established in time, closing")
				return
			}
		}
	}
}

func (self *multiListener) accept(conn edge.Conn, ticker *time.Ticker) {
	for !self.closed.Load() {
		select {
		case self.acceptC <- conn:
			return
		case <-ticker.C:
			// lets us check if the listener is closed, and exit if it has
		}
	}
}

func (self *multiListener) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		self.listenerLock.Lock()
		defer self.listenerLock.Unlock()

		var resultErrors []error
		for child := range self.listeners {
			if err := child.Close(); err != nil {
				resultErrors = append(resultErrors, err)
			}
		}

		self.listeners = nil

		select {
		case self.acceptC <- nil:
		default:
			// If the queue is full, bail out, we're just popping a nil on the
			// accept queue to let it return from accept more quickly
		}

		return self.condenseErrors(resultErrors)
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
