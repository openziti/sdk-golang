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
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// countingControlChannel is a NoopTestChannel whose Send counts messages, so a
// test can observe control responses (e.g. trace-route replies) emitted via the
// conn's control sender.
type countingControlChannel struct {
	NoopTestChannel
	sends atomic.Int32
}

func (ch *countingControlChannel) Send(channel.Sendable) error {
	ch.sends.Add(1)
	return nil
}

// noopTestMetrics implements xgress.Metrics for receive-path tests.
type noopTestMetrics struct{}

func (noopTestMetrics) MarkAckReceived()               {}
func (noopTestMetrics) MarkPayloadDropped()            {}
func (noopTestMetrics) MarkDuplicateAck()              {}
func (noopTestMetrics) MarkDuplicatePayload()          {}
func (noopTestMetrics) BufferBlockedByLocalWindow()    {}
func (noopTestMetrics) BufferUnblockedByLocalWindow()  {}
func (noopTestMetrics) BufferBlockedByRemoteWindow()   {}
func (noopTestMetrics) BufferUnblockedByRemoteWindow() {}
func (noopTestMetrics) PayloadWritten(time.Duration)   {}
func (noopTestMetrics) BufferUnblocked(time.Duration)  {}
func (noopTestMetrics) SendPayloadBuffered(int64)      {}
func (noopTestMetrics) SendPayloadDelivered(int64)     {}
func (noopTestMetrics) MarkRetransmission()            {}
func (noopTestMetrics) MarkRetransmissionFailure()     {}

// TestReceiveConvergenceAckAffinity exercises the full receive path: a
// payload arriving via one of multiple paths converges on the single bound
// xgress, and the per-payload ack is sent back over the arrival path, not
// the primary.
func TestReceiveConvergenceAckAffinity(t *testing.T) {
	req := require.New(t)

	closeNotify := make(chan struct{})
	defer close(closeNotify)

	env := testEnv{ingester: xgress.NewPayloadIngester(closeNotify), metrics: noopTestMetrics{}}

	pathA, senderA := newTestPath("a", 1)
	pathB, senderB := newTestPath("b", 2)

	adapter := NewMultiPathAdapter("c1", env, SinglePathSelector{}, pathA)
	xg := xgress.NewXgress("c1", "ctrl", "addr", adapter, xgress.Initiator, xgress.DefaultOptions(), nil)
	adapter.xg = xg
	xg.SetDataPlaneAdapter(adapter)

	conn := &edgeConnXgress{
		edgeConnBase: edgeConnBase{circuitId: "c1", closeNotify: make(chan struct{})},
		adapter:      adapter,
		xg:           xg,
		localId:      nextLocalConnId(),
	}
	adapter.AddPath(pathB)

	// a payload arriving via path B is acked over path B, not the primary
	payload := &xgress.Payload{
		CircuitId: "c1",
		Flags:     xgress.SetOriginatorFlag(0, xgress.Terminator),
		Sequence:  1,
		Data:      []byte("hello"),
	}
	conn.acceptPathMessage(pathB, payload.Marshall(), nil)

	req.Eventually(func() bool { return senderB.acks.Load() == 1 }, time.Second, 5*time.Millisecond)
	req.EqualValues(0, senderA.acks.Load())

	// a payload arriving via the primary is acked over the primary
	payload2 := &xgress.Payload{
		CircuitId: "c1",
		Flags:     xgress.SetOriginatorFlag(0, xgress.Terminator),
		Sequence:  2,
		Data:      []byte("world"),
	}
	conn.acceptPathMessage(pathA, payload2.Marshall(), nil)

	req.Eventually(func() bool { return senderA.acks.Load() == 1 }, time.Second, 5*time.Millisecond)
	req.EqualValues(1, senderB.acks.Load())

	// a duplicate copy of an already-received payload arriving on a different
	// path is acked over ITS arrival path: the receiver acks duplicates, and
	// each copy's ack returns on the path that copy traveled
	dup := &xgress.Payload{
		CircuitId: "c1",
		Flags:     xgress.SetOriginatorFlag(0, xgress.Terminator),
		Sequence:  1,
		Data:      []byte("hello"),
	}
	conn.acceptPathMessage(pathA, dup.Marshall(), nil)

	req.Eventually(func() bool { return senderA.acks.Load() == 2 }, time.Second, 5*time.Millisecond)
	req.EqualValues(1, senderB.acks.Load())

	// a payload with a mismatched circuit id is dropped: no ack, no close
	wrong := &xgress.Payload{
		CircuitId: "other-circuit",
		Flags:     xgress.SetOriginatorFlag(0, xgress.Terminator),
		Sequence:  3,
		Data:      []byte("intruder"),
	}
	conn.acceptPathMessage(pathB, wrong.Marshall(), nil)

	time.Sleep(50 * time.Millisecond)
	req.EqualValues(2, senderA.acks.Load())
	req.EqualValues(1, senderB.acks.Load())
	req.False(xg.IsClosed())

	// an ack with a mismatched circuit id is also dropped without closing
	wrongAck := xgress.NewAcknowledgement("other-circuit", xgress.Terminator)
	conn.acceptPathMessage(pathB, wrongAck.Marshall(), nil)
	time.Sleep(20 * time.Millisecond)
	req.False(xg.IsClosed())
}

// TestReceiveControlCircuitIdMismatch verifies inbound xgress control messages
// are validated against the conn's circuit id: a trace-route request for this
// circuit is answered, but one carrying a stale/foreign circuit id is dropped
// rather than answered for the wrong circuit.
func TestReceiveControlCircuitIdMismatch(t *testing.T) {
	req := require.New(t)

	closeNotify := make(chan struct{})
	defer close(closeNotify)

	env := testEnv{ingester: xgress.NewPayloadIngester(closeNotify), metrics: noopTestMetrics{}}
	path, _ := newTestPath("a", 1)
	adapter := NewMultiPathAdapter("c1", env, SinglePathSelector{}, path)
	xg := xgress.NewXgress("c1", "ctrl", "addr", adapter, xgress.Terminator, xgress.DefaultOptions(), nil)
	adapter.xg = xg
	xg.SetDataPlaneAdapter(adapter)

	conn := &edgeConnXgress{
		edgeConnBase: edgeConnBase{circuitId: "c1", closeNotify: make(chan struct{})},
		adapter:      adapter,
		xg:           xg,
		localId:      nextLocalConnId(),
	}

	ctrlCh := &countingControlChannel{}
	sdkCh := edge.NewSingleSdkChannel(ctrlCh)

	traceRoute := func(circuitId string) *channel.Message {
		ctrl := &xgress.Control{Type: xgress.ControlTypeTraceRoute, CircuitId: circuitId, Headers: channel.Headers{}}
		ctrl.Headers.PutUint32Header(xgress.ControlHopCount, 1)
		return ctrl.Marshall()
	}

	// a trace-route control for this conn's circuit is answered
	conn.acceptPathMessage(path, traceRoute("c1"), sdkCh)
	req.Eventually(func() bool { return ctrlCh.sends.Load() == 1 }, time.Second, 5*time.Millisecond)

	// one carrying a foreign circuit id is dropped: no further response is sent
	conn.acceptPathMessage(path, traceRoute("other-circuit"), sdkCh)
	time.Sleep(50 * time.Millisecond)
	req.EqualValues(1, ctrlCh.sends.Load())
	req.False(xg.IsClosed())
}
