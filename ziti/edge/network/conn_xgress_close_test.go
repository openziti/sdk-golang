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
	"testing"
	"time"

	"github.com/openziti/channel/v4"
	"github.com/openziti/metrics"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// unackedTestChannel accepts everything sent on it and never replies, so nothing an xgress sends
// through it is acknowledged.
type unackedTestChannel struct {
	NoopTestChannel
	closeNotify chan struct{}
}

func newUnackedTestChannel() *unackedTestChannel {
	return &unackedTestChannel{closeNotify: make(chan struct{})}
}

// Send reports s written, as a channel does once the bytes reach the wire.
func (ch *unackedTestChannel) Send(s channel.Sendable) error {
	if listener := s.SendListener(); listener != nil {
		listener.NotifyQueued()
		listener.NotifyBeforeWrite()
		listener.NotifyAfterWrite()
	}
	return nil
}

func (ch *unackedTestChannel) TrySend(s channel.Sendable) (bool, error) {
	return true, ch.Send(s)
}

func (ch *unackedTestChannel) Id() string {
	return "test-router"
}

func (ch *unackedTestChannel) LogicalName() string {
	return "test-router"
}

func (ch *unackedTestChannel) ConnectionId() string {
	return "test-connection"
}

func (ch *unackedTestChannel) CloseNotify() <-chan struct{} {
	return ch.closeNotify
}

func (ch *unackedTestChannel) IsClosed() bool {
	return false
}

type testXgressEnv struct {
	payloadIngester *xgress.PayloadIngester
	metrics         xgress.Metrics
}

func (env *testXgressEnv) GetPayloadIngester() *xgress.PayloadIngester {
	return env.payloadIngester
}

func (env *testXgressEnv) GetMetrics() xgress.Metrics {
	return env.metrics
}

// newXgressCloseTestConn builds a conn with xgress flow control, wired to a mux and an
// unacknowledging test channel the way the dial path does, and starts its xgress.
func newXgressCloseTestConn(t *testing.T) (*edgeConn, edge.ConnMux[any]) {
	t.Helper()

	envCloseNotify := make(chan struct{})
	t.Cleanup(func() { close(envCloseNotify) })
	envF := func() xgress.Env {
		return &testXgressEnv{
			payloadIngester: xgress.NewPayloadIngester(envCloseNotify),
			metrics:         xgress.NewMetrics(metrics.NewRegistry("test", nil)),
		}
	}

	closeNotify := make(chan struct{})
	mux := edge.NewChannelConnMapMux[any](nil)
	testChannel := edge.NewSingleSdkChannel(newUnackedTestChannel())
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:       NewNoopSequencer[*channel.Message](closeNotify, 4),
		msgMux:      mux,
		serviceName: "test",
		closeNotify: closeNotify,
		circuitId:   "test-circuit",
	}
	require.NoError(t, mux.Add(conn))

	reply := edge.NewStateConnectedMsg(conn.Id())
	reply.PutBoolHeader(edge.UseXgressToSdkHeader, true)
	reply.PutStringHeader(edge.XgressCtrlIdHeader, "test-ctrl")
	reply.PutStringHeader(edge.XgressAddressHeader, "test-address")
	require.NoError(t, conn.setupFlowControl(reply, xgress.Initiator, envF))
	return conn, mux
}

// A conn closed locally keeps its xgress, and its mux entry, while unacknowledged payloads drain.
// A StateClosed then means routing has gone and nothing can drain, so the xgress tears down and the
// conn leaves the mux instead of retransmitting forever.
func Test_XgressConn_StateClosedAfterLocalCloseTearsDown(t *testing.T) {
	req := require.New(t)
	conn, mux := newXgressCloseTestConn(t)

	_, err := conn.Write([]byte("never acknowledged"))
	req.NoError(err)
	req.NoError(conn.Close())

	req.Never(func() bool {
		_, found := mux.GetSinks()[conn.Id()]
		return !found
	}, 250*time.Millisecond, 10*time.Millisecond, "the conn left the mux with payloads still unacknowledged")

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))

	req.Eventually(func() bool {
		_, found := mux.GetSinks()[conn.Id()]
		return !found
	}, 5*time.Second, 10*time.Millisecond, "the conn stayed in the mux after the router closed its circuit")
	req.True(conn.xgCircuit.xg.IsClosed())
}
