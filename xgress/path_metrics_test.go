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

package xgress

import (
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// retransmitCountingMetrics counts retransmit metric calls for assertions.
type retransmitCountingMetrics struct {
	noopMetrics
	retransmits atomic.Int32
	failures    atomic.Int32
}

func (m *retransmitCountingMetrics) MarkRetransmission()        { m.retransmits.Add(1) }
func (m *retransmitCountingMetrics) MarkRetransmissionFailure() { m.failures.Add(1) }

// flagRecordingAdapter records the retransmit flag seen on each (re)transmitted
// payload, so a test can assert whether a send was labeled a retransmit.
type flagRecordingAdapter struct {
	noopReceiveHandler
	metrics *retransmitCountingMetrics
	flags   []bool
}

func (a *flagRecordingAdapter) GetMetrics() Metrics { return a.metrics }

func (a *flagRecordingAdapter) RetransmitPayload(_ Path, _ Address, payload *Payload) (Path, error) {
	a.flags = append(a.flags, payload.IsRetransmitFlagSet())
	return testPath("test"), nil
}

// recordingTag is a Path implementation that captures
// the per-path samples the send buffer attributes to it.
type recordingTag struct {
	id     string
	rtts   []uint16
	losses int
}

func (t *recordingTag) ID() string              { return t.id }
func (t *recordingTag) RecordRtt(sample uint16) { t.rtts = append(t.rtts, sample) }
func (t *recordingTag) RecordLoss()             { t.losses++ }

func newMetricsTestBuffer() *LinkSendBuffer {
	x := NewXgress("c1", "ctrl", "addr", nil, Initiator, DefaultOptions(), nil)
	x.SetDataPlaneAdapter(noopReceiveHandler{})
	return x.payloadBuffer
}

// recentRtt returns an ack RTT stamp that the buffer will read as roughly
// sampleMillis of round-trip time.
func recentRtt(sampleMillis uint16) uint16 {
	return uint16(time.Now().UnixMilli()) - sampleMillis
}

// TestPerPathRttByArrivalPath: a nonzero-RTT ack attributes its sample to the
// path it arrived on, not to any other path.
func TestPerPathRttByArrivalPath(t *testing.T) {
	req := require.New(t)
	buffer := newMetricsTestBuffer()

	tagA := &recordingTag{id: "a"}
	tagB := &recordingTag{id: "b"}

	ack := NewAcknowledgement("c1", Initiator)
	ack.RTT = recentRtt(10)
	ack.SetArrivalPath(tagB)
	buffer.receiveAcknowledgement(ack)

	req.Len(tagB.rtts, 1)
	req.Empty(tagA.rtts)
	req.Positive(tagB.rtts[0])
}

// TestPerPathLossByLastSendPath: a payload retransmitted away from a path
// charges the loss to the path it was last sent on.
func TestPerPathLossByLastSendPath(t *testing.T) {
	req := require.New(t)
	buffer := newMetricsTestBuffer()

	tagA := &recordingTag{id: "a"}
	txp := &txPayload{payload: &Payload{CircuitId: "c1", Sequence: 1}, x: buffer.x}
	txp.markSentOn(tagA)
	atomic.StoreInt64(&txp.age, time.Now().UnixMilli()-100_000) // long overdue
	buffer.buffer[1] = txp
	buffer.retxThreshold = 1

	buffer.retransmit()

	req.Equal(1, tagA.losses)
}

// TestPerPathCrossPathRetransmit: a payload sent on A, retransmitted on B, then
// acked from B yields a clean RTT sample for B and a loss count against A.
func TestPerPathCrossPathRetransmit(t *testing.T) {
	req := require.New(t)
	buffer := newMetricsTestBuffer()

	tagA := &recordingTag{id: "a"}
	tagB := &recordingTag{id: "b"}

	txp := &txPayload{payload: &Payload{CircuitId: "c1", Sequence: 1}, x: buffer.x}
	txp.markSentOn(tagA)
	atomic.StoreInt64(&txp.age, time.Now().UnixMilli()-100_000)
	buffer.buffer[1] = txp
	buffer.retxThreshold = 1

	// retransmit: loss charged to the last-send path (A)
	buffer.retransmit()
	req.Equal(1, tagA.losses)
	req.Zero(tagB.losses)

	// the retransmit was accepted on B: the stored tag advances
	txp.markSentOn(tagB)

	// ack returns on B (arrival affinity): RTT sample attributed to B, not A
	ack := NewAcknowledgement("c1", Initiator)
	ack.RTT = recentRtt(20)
	ack.Sequence = []int32{1}
	ack.SetArrivalPath(tagB)
	buffer.receiveAcknowledgement(ack)

	req.Len(tagB.rtts, 1)
	req.Empty(tagA.rtts)
	req.Empty(buffer.buffer) // delivered: entry removed
}

// TestPerPathDuplicateAckSinglePath: when only one copy of a payload arrives,
// exactly one RTT sample is recorded on its arrival path.
func TestPerPathDuplicateAckSinglePath(t *testing.T) {
	req := require.New(t)
	buffer := newMetricsTestBuffer()

	tagB := &recordingTag{id: "b"}
	txp := &txPayload{payload: &Payload{CircuitId: "c1", Sequence: 1}, x: buffer.x}
	txp.markSentOn(tagB)
	buffer.buffer[1] = txp

	ack := NewAcknowledgement("c1", Initiator)
	ack.RTT = recentRtt(15)
	ack.Sequence = []int32{1}
	ack.SetArrivalPath(tagB)
	buffer.receiveAcknowledgement(ack)

	req.Len(tagB.rtts, 1)
	req.Empty(buffer.buffer)
}

// TestPerPathDuplicateAckBothCopies: when both copies of a cross-path
// retransmit arrive (the A copy was slow, not lost), each arrival path gets its
// own RTT sample, but delivery/loss state mutates exactly once.
func TestPerPathDuplicateAckBothCopies(t *testing.T) {
	req := require.New(t)
	buffer := newMetricsTestBuffer()

	tagA := &recordingTag{id: "a"}
	tagB := &recordingTag{id: "b"}

	txp := &txPayload{payload: &Payload{CircuitId: "c1", Sequence: 1}, x: buffer.x}
	txp.markSentOn(tagB) // last sent on B
	buffer.buffer[1] = txp

	// first ack: the B copy arrives, removes the in-flight entry
	ackB := NewAcknowledgement("c1", Initiator)
	ackB.RTT = recentRtt(20)
	ackB.Sequence = []int32{1}
	ackB.SetArrivalPath(tagB)
	buffer.receiveAcknowledgement(ackB)

	req.Empty(buffer.buffer)
	req.EqualValues(1, buffer.successfulAcks)

	// second ack: the slow A copy arrives, a duplicate. It still measures A's
	// round trip, but must not re-touch delivery state.
	ackA := NewAcknowledgement("c1", Initiator)
	ackA.RTT = recentRtt(80)
	ackA.Sequence = []int32{1}
	ackA.SetArrivalPath(tagA)
	buffer.receiveAcknowledgement(ackA)

	req.Len(tagB.rtts, 1)
	req.Len(tagA.rtts, 1)
	req.EqualValues(1, buffer.successfulAcks) // unchanged
	req.EqualValues(1, buffer.duplicateAcks)  // the A copy counted as a duplicate
}

// TestPerPathNilTagsSafe: acks/payloads with no path tag (window updates,
// never-sent payloads) record nothing and do not panic.
func TestPerPathNilTagsSafe(t *testing.T) {
	req := require.New(t)
	buffer := newMetricsTestBuffer()

	// ack with a nonzero RTT but no arrival tag
	ack := NewAcknowledgement("c1", Initiator)
	ack.RTT = recentRtt(10)
	req.NotPanics(func() { buffer.receiveAcknowledgement(ack) })
}

// TestSendQueuedPayloadFirstSendNotRetransmit verifies that a never-sent payload
// requeued through the retransmit path (as a pathless flush does) has its first
// transmission sent WITHOUT the retransmit flag and uncounted as a retransmit,
// so the receiver meters it once; a genuinely re-sent payload is flagged/counted.
func TestSendQueuedPayloadFirstSendNotRetransmit(t *testing.T) {
	req := require.New(t)
	metrics := &retransmitCountingMetrics{}
	adapter := &flagRecordingAdapter{metrics: metrics}
	x := NewXgress("c1", "ctrl", "addr", nil, Initiator, DefaultOptions(), nil)
	x.SetDataPlaneAdapter(adapter)
	buffer := x.payloadBuffer

	// never-sent payload (age at its initial max): first transmission
	neverSent := &txPayload{payload: &Payload{CircuitId: "c1", Sequence: 1}, age: math.MaxInt64, x: x}
	buffer.sendQueuedPayload(neverSent)
	req.Equal([]bool{false}, adapter.flags)
	req.False(neverSent.payload.IsRetransmitFlagSet())
	req.EqualValues(0, metrics.retransmits.Load())

	// already-sent payload: genuine retransmit
	sent := &txPayload{payload: &Payload{CircuitId: "c1", Sequence: 2}, x: x}
	sent.markSentOn(testPath("test")) // sets age to now
	buffer.sendQueuedPayload(sent)
	req.Equal([]bool{false, true}, adapter.flags)
	req.True(sent.payload.IsRetransmitFlagSet())
	req.EqualValues(1, metrics.retransmits.Load())
}
