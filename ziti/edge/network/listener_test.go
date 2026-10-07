/*
	Copyright NetFoundry Inc.

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
	"sync"
	"testing"
	"time"

	"github.com/openziti/channel/v4"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// sendCapturingChannel records every message sent on it and reports each as written, so
// SendAndWaitForWire returns at once.
type sendCapturingChannel struct {
	channel.Channel
	lock        sync.Mutex
	sent        []*channel.Message
	closeNotify chan struct{}
}

func newSendCapturingChannel() *sendCapturingChannel {
	return &sendCapturingChannel{closeNotify: make(chan struct{})}
}

func (ch *sendCapturingChannel) Send(s channel.Sendable) error {
	ch.lock.Lock()
	ch.sent = append(ch.sent, s.Msg())
	ch.lock.Unlock()
	s.SendListener().NotifyAfterWrite()
	return nil
}

func (ch *sendCapturingChannel) CloseNotify() <-chan struct{} { return ch.closeNotify }
func (ch *sendCapturingChannel) IsClosed() bool               { return false }
func (ch *sendCapturingChannel) Label() string                { return "test" }

// takeUpdateBinds returns the update bind messages sent since the last call.
func (ch *sendCapturingChannel) takeUpdateBinds() []*channel.Message {
	ch.lock.Lock()
	defer ch.lock.Unlock()
	var result []*channel.Message
	for _, msg := range ch.sent {
		if msg.ContentType == edge.ContentTypeUpdateBind {
			result = append(result, msg)
		}
	}
	ch.sent = nil
	return result
}

type multiListenerTest struct {
	t       *testing.T
	ch      *sendCapturingChannel
	router  *routerConn
	service *rest_model.ServiceDetail
}

func newMultiListenerTest(t *testing.T) *multiListenerTest {
	ch := newSendCapturingChannel()
	serviceId, serviceName := "svc-id", "svc"
	service := &rest_model.ServiceDetail{Name: &serviceName}
	service.ID = &serviceId
	return &multiListenerTest{
		t:  t,
		ch: ch,
		router: &routerConn{
			routerName: "router",
			ch:         edge.NewSingleSdkChannel(ch),
			mux:        edge.NewChannelConnMapMux[any](nil),
		},
		service: service,
	}
}

func (self *multiListenerTest) newListener(cost uint16, precedence edge.Precedence) MultiListener {
	listener := NewMultiListener(self.service, cost, precedence, func() *rest_model.SessionDetail { return nil })
	self.t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// newChild returns a child listener whose bind carried cost and precedence.
func (self *multiListenerTest) newChild(cost uint16, precedence edge.Precedence) *edgeHostConn {
	token := "token"
	options := &edge.ListenOptions{Cost: cost, Precedence: precedence, EventHandler: noopListenerEventHandler{}}
	return self.router.NewListenConn(self.service, &rest_model.SessionDetail{Token: &token}, options, nil)
}

// addChild adds a child listener whose bind carried cost and precedence.
func (self *multiListenerTest) addChild(listener MultiListener, cost uint16, precedence edge.Precedence) *edgeHostConn {
	child := self.newChild(cost, precedence)
	listener.AddListener(child, func() {})
	return child
}

// confirm delivers a bind success to child and waits for the confirmation handler to finish.
func (self *multiListenerTest) confirm(child *edgeHostConn) {
	handler := child.confirmedHandler.Load()
	defer child.confirmedHandler.Store(handler)

	done := make(chan struct{})
	child.confirmedHandler.Store(func() {
		defer close(done)
		if handler != nil {
			handler()
		}
	})
	child.AcceptMessage(channel.NewMessage(edge.ContentTypeBindSuccess, nil))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		self.t.Fatal("timed out waiting for the bind success to be handled")
	}
}

type noopListenerEventHandler struct{}

func (noopListenerEventHandler) NotifyEstablished()  {}
func (noopListenerEventHandler) NotifyStartOver()    {}
func (noopListenerEventHandler) NotifyNotRetriable() {}

func requireUpdateBind(t *testing.T, msg *channel.Message, cost *uint16, precedence *edge.Precedence) {
	actualCost, hasCost := msg.GetUint16Header(edge.CostHeader)
	require.Equal(t, cost != nil, hasCost)
	if cost != nil {
		require.Equal(t, *cost, actualCost)
	}

	actualPrecedence, hasPrecedence := msg.Headers[edge.PrecedenceHeader]
	require.Equal(t, precedence != nil, hasPrecedence)
	if precedence != nil {
		require.Equal(t, []byte{byte(*precedence)}, actualPrecedence)
	}
}

func ptr[T any](v T) *T {
	return &v
}

// Updates are recorded for later binds, and each sends only the values it names to confirmed children.
func Test_MultiListener_UpdatesRecordedForNewBinds(t *testing.T) {
	req := require.New(t)
	test := newMultiListenerTest(t)
	listener := test.newListener(3, edge.PrecedenceDefault)

	cost, precedence := listener.GetCostAndPrecedence()
	req.Equal(uint16(3), cost)
	req.Equal(edge.PrecedenceDefault, precedence)

	child := test.addChild(listener, 3, edge.PrecedenceDefault)
	test.confirm(child)
	req.Empty(test.ch.takeUpdateBinds())

	req.NoError(listener.UpdateCost(7))
	cost, precedence = listener.GetCostAndPrecedence()
	req.Equal(uint16(7), cost)
	req.Equal(edge.PrecedenceDefault, precedence)
	updates := test.ch.takeUpdateBinds()
	req.Len(updates, 1)
	requireUpdateBind(t, updates[0], ptr(uint16(7)), nil)

	req.NoError(listener.UpdatePrecedence(edge.PrecedenceRequired))
	cost, precedence = listener.GetCostAndPrecedence()
	req.Equal(uint16(7), cost)
	req.Equal(edge.PrecedenceRequired, precedence)
	updates = test.ch.takeUpdateBinds()
	req.Len(updates, 1)
	requireUpdateBind(t, updates[0], nil, ptr(edge.PrecedenceRequired))

	req.NoError(listener.UpdateCostAndPrecedence(9, edge.PrecedenceFailed))
	cost, precedence = listener.GetCostAndPrecedence()
	req.Equal(uint16(9), cost)
	req.Equal(edge.PrecedenceFailed, precedence)
	updates = test.ch.takeUpdateBinds()
	req.Len(updates, 1)
	requireUpdateBind(t, updates[0], ptr(uint16(9)), ptr(edge.PrecedenceFailed))
}

// An update made before a child's bind is confirmed reaches the child when it is confirmed.
func Test_MultiListener_UpdateBeforeConfirmationSentOnConfirmation(t *testing.T) {
	req := require.New(t)
	test := newMultiListenerTest(t)
	listener := test.newListener(3, edge.PrecedenceDefault)
	child := test.addChild(listener, 3, edge.PrecedenceDefault)

	req.NoError(listener.UpdateCostAndPrecedence(7, edge.PrecedenceRequired))
	req.Empty(test.ch.takeUpdateBinds())

	test.confirm(child)
	updates := test.ch.takeUpdateBinds()
	req.Len(updates, 1)
	requireUpdateBind(t, updates[0], ptr(uint16(7)), ptr(edge.PrecedenceRequired))
}

// Once the listener has been updated, every confirmation sends the recorded values, including one for
// a bind that already carried them.
func Test_MultiListener_EveryConfirmationReconciledAfterUpdate(t *testing.T) {
	req := require.New(t)
	test := newMultiListenerTest(t)
	listener := test.newListener(3, edge.PrecedenceDefault)
	req.NoError(listener.UpdateCostAndPrecedence(7, edge.PrecedenceRequired))

	child := test.addChild(listener, 7, edge.PrecedenceRequired)
	req.Empty(test.ch.takeUpdateBinds())

	for range 2 {
		test.confirm(child)
		updates := test.ch.takeUpdateBinds()
		req.Len(updates, 1)
		requireUpdateBind(t, updates[0], ptr(uint16(7)), ptr(edge.PrecedenceRequired))
	}
}

// A listener that was never updated sends nothing on confirmation.
func Test_MultiListener_ConfirmationWithoutUpdateSendsNothing(t *testing.T) {
	req := require.New(t)
	test := newMultiListenerTest(t)
	listener := test.newListener(3, edge.PrecedenceDefault)
	child := test.addChild(listener, 3, edge.PrecedenceDefault)

	test.confirm(child)
	req.Empty(test.ch.takeUpdateBinds())
}

// A child confirmed before it is added is reconciled as it is added.
func Test_MultiListener_ConfirmedBeforeAddReconciled(t *testing.T) {
	req := require.New(t)
	test := newMultiListenerTest(t)
	listener := test.newListener(3, edge.PrecedenceDefault)
	req.NoError(listener.UpdateCostAndPrecedence(7, edge.PrecedenceRequired))

	child := test.newChild(7, edge.PrecedenceRequired)
	test.confirm(child)
	req.Empty(test.ch.takeUpdateBinds())

	listener.AddListener(child, func() {})
	updates := test.ch.takeUpdateBinds()
	req.Len(updates, 1)
	requireUpdateBind(t, updates[0], ptr(uint16(7)), ptr(edge.PrecedenceRequired))
}
