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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/metrics"
	"github.com/openziti/sdk-golang/v2/secretstream/kx"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// acceptTestChannel completes every send at once and records the content types sent, along with
// those sent without a deadline.
type acceptTestChannel struct {
	NoopTestChannel
	sync.Mutex
	sent        []int32
	unbounded   []int32
	closeNotify chan struct{}
}

func (ch *acceptTestChannel) CloseNotify() <-chan struct{} { return ch.closeNotify }
func (ch *acceptTestChannel) Id() string                   { return "test-router" }
func (ch *acceptTestChannel) LogicalName() string          { return "test" }
func (ch *acceptTestChannel) IsClosed() bool               { return false }

func (ch *acceptTestChannel) Send(s channel.Sendable) error {
	_, bounded := s.Context().Deadline()
	ch.Lock()
	ch.sent = append(ch.sent, s.Msg().ContentType)
	if !bounded {
		ch.unbounded = append(ch.unbounded, s.Msg().ContentType)
	}
	ch.Unlock()
	s.SendListener().NotifyQueued()
	s.SendListener().NotifyBeforeWrite()
	s.SendListener().NotifyAfterWrite()
	return nil
}

func (ch *acceptTestChannel) sentTypes() []int32 {
	ch.Lock()
	defer ch.Unlock()
	return append([]int32(nil), ch.sent...)
}

func (ch *acceptTestChannel) unboundedTypes() []int32 {
	ch.Lock()
	defer ch.Unlock()
	return append([]int32(nil), ch.unbounded...)
}

type acceptTestEnv struct {
	ingester *xgress.PayloadIngester
	metrics  xgress.Metrics
}

func (e *acceptTestEnv) GetPayloadIngester() *xgress.PayloadIngester { return e.ingester }
func (e *acceptTestEnv) GetMetrics() xgress.Metrics                  { return e.metrics }

// newAcceptTestHost builds a hosting conn wired to a mux and a test channel, so dials handed to
// newChildConnection build and start hosted xgress conns the way they do in production.
func newAcceptTestHost(t *testing.T, manualStart bool) (*edgeHostConn, *acceptTestChannel, edge.ConnMux[any]) {
	closeNotify := make(chan struct{})
	t.Cleanup(func() { close(closeNotify) })
	env := &acceptTestEnv{
		ingester: xgress.NewPayloadIngester(closeNotify),
		metrics:  xgress.NewMetrics(metrics.NewRegistry("test", nil)),
	}
	testCh := &acceptTestChannel{closeNotify: closeNotify}
	mux := edge.NewChannelConnMapMux[any](nil)
	name := "svc"
	host := &edgeHostConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(edge.NewSingleSdkChannel(testCh), 1),
		msgMux:      mux,
		serviceName: name,
		service:     &rest_model.ServiceDetail{Name: &name},
		acceptC:     make(chan edge.Conn, 10),
		token:       "token",
		manualStart: manualStart,
		envF:        func() xgress.Env { return env },
	}
	return host, testCh, mux
}

// newXgressDialMsg builds a router dial for an SDK-hosted xgress conn. No circuit start follows
// it, so the conn's circuit never starts.
func newXgressDialMsg(connId uint32) *channel.Message {
	msg := edge.NewDialMsg(1, "token", "caller")
	msg.PutStringHeader(edge.CircuitIdHeader, "circuit-1")
	msg.PutBoolHeader(edge.UseXgressToSdkHeader, true)
	msg.PutStringHeader(edge.XgressCtrlIdHeader, "ctrl")
	msg.PutStringHeader(edge.XgressAddressHeader, "addr")
	msg.PutUint32Header(edge.RouterProvidedConnId, connId)
	return msg
}

func requireReturnsWithin(t *testing.T, d time.Duration, what string, f func()) {
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// Closing a hosted conn after refusing its dial tears it down at once, rather than waiting
// out the circuit start timeout.
func Test_HostedXgressConn_CloseAfterAcceptFailed(t *testing.T) {
	req := require.New(t)
	host, ch, mux := newAcceptTestHost(t, true)

	host.newChildConnection(newXgressDialMsg(42), host.SdkChannel)
	conn := <-host.acceptC
	conn.CompleteAcceptFailed(errors.New("target down"))
	req.Contains(ch.sentTypes(), int32(edge.ContentTypeDialFailed))

	requireReturnsWithin(t, 5*time.Second, "Close", func() { _ = conn.Close() })
	req.True(conn.IsClosed())
	requireMuxHasConn(t, mux, 42, false)
}

// Closing a hosted conn whose accept was never completed tears it down at once.
func Test_HostedXgressConn_CloseWithoutCompletingAccept(t *testing.T) {
	req := require.New(t)
	host, _, mux := newAcceptTestHost(t, true)

	host.newChildConnection(newXgressDialMsg(43), host.SdkChannel)
	conn := <-host.acceptC

	requireReturnsWithin(t, 5*time.Second, "Close", func() { _ = conn.Close() })
	req.True(conn.IsClosed())
	requireMuxHasConn(t, mux, 43, false)
}

// A dial that fails setup after its xgress has started is cleaned up and reported to the
// router at once.
func Test_HostedXgressConn_SetupFailureReportsPromptly(t *testing.T) {
	req := require.New(t)
	host, ch, mux := newAcceptTestHost(t, false)
	kp, err := kx.NewKeyPair()
	req.NoError(err)
	host.crypto = true
	host.keyPair = kp

	msg := newXgressDialMsg(44)
	msg.Headers[edge.PublicKeyHeader] = kp.Public()
	msg.PutByteHeader(edge.CryptoMethodHeader, 99)

	requireReturnsWithin(t, 5*time.Second, "newChildConnection", func() {
		host.newChildConnection(msg, host.SdkChannel)
	})
	req.Contains(ch.sentTypes(), int32(edge.ContentTypeDialFailed))
	requireMuxHasConn(t, mux, 44, false)
}

// A dial that reuses the id of a registered conn is refused without disturbing that conn.
func Test_HostedXgressConn_DuplicateIdLeavesLiveConn(t *testing.T) {
	req := require.New(t)
	host, ch, mux := newAcceptTestHost(t, true)

	host.newChildConnection(newXgressDialMsg(47), host.SdkChannel)
	live := <-host.acceptC

	requireReturnsWithin(t, 5*time.Second, "newChildConnection", func() {
		host.newChildConnection(newXgressDialMsg(47), host.SdkChannel)
	})
	req.Contains(ch.sentTypes(), int32(edge.ContentTypeDialFailed))
	req.False(live.IsClosed())
	sink, found := mux.GetSinks()[47]
	req.True(found, "the live conn was removed from the mux")
	req.Same(live, sink)
}

// Every send a pre-start Close makes carries a deadline, so a stalled router channel cannot
// hold Close or the mux removal behind it.
func Test_HostedXgressConn_PreStartCloseSendsAreBounded(t *testing.T) {
	req := require.New(t)
	host, ch, mux := newAcceptTestHost(t, true)

	host.newChildConnection(newXgressDialMsg(48), host.SdkChannel)
	conn := <-host.acceptC
	conn.CompleteAcceptFailed(errors.New("target down"))
	_ = conn.Close()

	req.Contains(ch.sentTypes(), int32(xgress.ContentTypePayloadType))
	req.Empty(ch.unboundedTypes())
	requireMuxHasConn(t, mux, 48, false)
}
