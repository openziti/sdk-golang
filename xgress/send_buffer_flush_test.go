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
	"errors"
	"math"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newFlushTestBuffer returns a send buffer whose data plane accepts every send and
// whose run loop is not started, so a test can drive flush events and path changes
// by hand.
func newFlushTestBuffer() *LinkSendBuffer {
	x := NewXgress("c1", "ctrl", "addr", nil, Initiator, DefaultOptions(), nil)
	x.SetDataPlaneAdapter(noopReceiveHandler{})
	return x.payloadBuffer
}

// failingSendAdapter fails every send, either with an error or by reporting that no
// path took the payload, so a test can exercise both ways a send can fail to land.
type failingSendAdapter struct {
	noopReceiveHandler
	err      error
	attempts atomic.Int32
}

func (a *failingSendAdapter) RetransmitPayload(_ Path, _ Address, _ *Payload) (Path, error) {
	a.attempts.Add(1)
	return nil, a.err
}

// newFailingSendBuffer returns a send buffer whose data plane fails every send,
// standing in for a circuit with no usable path.
func newFailingSendBuffer(err error) (*LinkSendBuffer, *failingSendAdapter) {
	adapter := &failingSendAdapter{err: err}
	x := NewXgress("c1", "ctrl", "addr", nil, Initiator, DefaultOptions(), nil)
	x.SetDataPlaneAdapter(adapter)
	return x.payloadBuffer, adapter
}

// drainRetransmits pops the retransmit list, returning the sequence numbers in the
// order the sender would transmit them. It releases each payload's queue slot as
// retransmitSender does, so a payload that has been transmitted looks the same here
// as it does in production.
func drainRetransmits(buffer *LinkSendBuffer) []int32 {
	var result []int32
	for p := buffer.retransmitPop(); p != nil; p = buffer.retransmitPop() {
		result = append(result, p.payload.Sequence)
		p.dequeued()
	}
	return result
}

// senderFails models the retransmit sender popping one payload and failing to place
// it on any path.
func senderFails(buffer *LinkSendBuffer) {
	p := buffer.retransmitPop()
	if p == nil {
		return
	}
	buffer.sendQueuedPayload(p)
	p.dequeued()
}

// pathlessSeqs returns the sequence numbers still awaiting a first send, sorted so
// assertions do not depend on map iteration order.
func pathlessSeqs(buffer *LinkSendBuffer) []int32 {
	buffer.pathlessLock.Lock()
	defer buffer.pathlessLock.Unlock()

	var result []int32
	for seq := range buffer.pathless {
		result = append(result, seq)
	}
	slices.Sort(result)
	return result
}

// flushNow runs a flush requested at this instant, as the run loop would.
func flushNow(buffer *LinkSendBuffer) {
	sendBufferFlushEvent{requestedAt: time.Now().UnixMilli()}.handle(buffer)
}

// markSentLongAgo marks a payload sent with a send time well in the past, so a
// flush requested now unambiguously covers it. Sends in the same millisecond as the
// request are deliberately treated as current, which would otherwise make these
// assertions depend on how fast the test runs.
func markSentLongAgo(p *txPayload, path Path) {
	p.markSentOn(path)
	atomic.StoreInt64(&p.age, time.Now().UnixMilli()-100_000)
}

// TestFlushExcludesNeverSentPayloads: the flush exists to move already-sent payloads
// onto a new path. A never-sent payload belongs to the pathless set, so re-queuing it
// here risks a duplicate first send.
func TestFlushExcludesNeverSentPayloads(t *testing.T) {
	req := require.New(t)
	buffer := newFlushTestBuffer()

	neverSent := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = neverSent

	flushNow(buffer)
	req.Empty(drainRetransmits(buffer), "flush queued a never-sent payload")
	req.True(neverSent.isRetransmittable(), "flush consumed the payload's queue slot")

	// a payload sent before the flush was requested is exactly what it is for
	sent := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 2})
	markSentLongAgo(sent, testPath("a"))
	buffer.buffer[2] = sent

	flushNow(buffer)
	req.Equal([]int32{2}, drainRetransmits(buffer))
}

// TestFlushExcludesSendsCompletedAfterRequest: the flush request reaches the run loop
// asynchronously, so the sender can carry a payload over the new path while it is
// queued. Such a payload is current, not stranded on the lost path, and re-sending it
// would put a redundant copy on the wire and count a retransmit that never happened.
func TestFlushExcludesSendsCompletedAfterRequest(t *testing.T) {
	req := require.New(t)
	buffer := newFlushTestBuffer()

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil) // no path took it, so it joins the set

	buffer.OnPathAvailable()

	// the sender carries it over the new path before the run loop sees the flush
	popped := buffer.retransmitPop()
	req.NotNil(popped, "the retry should hand the payload to the sender")
	req.EqualValues(1, popped.payload.Sequence)
	popped.markSentOn(testPath("b"))
	popped.dequeued()

	event := (<-buffer.events).(sendBufferFlushEvent)
	event.handle(buffer)

	req.Empty(drainRetransmits(buffer), "flush re-sent a payload that completed after it was requested")
}

// TestUnsentSendJoinsPathlessSet: a send that finds no path leaves the payload unsent,
// and nothing else revisits a never-sent payload, so it joins the set awaiting a first
// send and is attempted once immediately.
func TestUnsentSendJoinsPathlessSet(t *testing.T) {
	req := require.New(t)
	buffer, adapter := newFailingSendBuffer(nil)

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)

	req.Equal([]int32{1}, pathlessSeqs(buffer), "unsent payload did not join the pathless set")
	req.Equal([]int32{1}, drainRetransmits(buffer), "unsent payload was not attempted immediately")
	req.EqualValues(0, adapter.attempts.Load(), "the immediate attempt should be the sender's work, not the callback's")
}

// TestUnsentSendStaysUntilItLands: a failed attempt leaves the payload in the set, so
// a retry arriving at any point afterwards still finds it. The payload is never in
// transit between owners, so there is no moment at which a retry can miss it.
func TestUnsentSendStaysUntilItLands(t *testing.T) {
	req := require.New(t)
	buffer, adapter := newFailingSendBuffer(nil)

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)

	// the immediate attempt fails
	senderFails(buffer)
	req.EqualValues(1, adapter.attempts.Load())
	req.Equal([]int32{1}, pathlessSeqs(buffer), "a failed attempt dropped the payload")

	// so does a retry on the next path change
	buffer.RetryPathlessSends()
	senderFails(buffer)
	req.EqualValues(2, adapter.attempts.Load())
	req.Equal([]int32{1}, pathlessSeqs(buffer), "the payload stopped being retryable")

	// and it is still there for the one after that
	buffer.RetryPathlessSends()
	req.Equal([]int32{1}, drainRetransmits(buffer))
}

// TestFailedSendDoesNotRequeueItself: a failed attempt must not push the payload back
// onto the retransmit list. The sender pops in a tight loop, so re-pushing there would
// have the same goroutine re-pop and re-fail it without ever yielding.
func TestFailedSendDoesNotRequeueItself(t *testing.T) {
	req := require.New(t)
	buffer, adapter := newFailingSendBuffer(errors.New("channel closed"))

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)

	senderFails(buffer)

	req.Nil(buffer.retransmitPop(), "a failed send re-queued itself")
	req.EqualValues(1, adapter.attempts.Load(), "payload was retried without a path change")
	req.Equal([]int32{1}, pathlessSeqs(buffer))
}

// TestPathlessSetPrunesLandedSends: once a send lands, the retransmit timer owns the
// payload, so the set drops it rather than attempting it again.
func TestPathlessSetPrunesLandedSends(t *testing.T) {
	req := require.New(t)
	buffer := newFlushTestBuffer()

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)
	req.Equal([]int32{1}, pathlessSeqs(buffer))

	// the sender places it on a path
	popped := buffer.retransmitPop()
	req.NotNil(popped)
	popped.markSentOn(testPath("a"))
	popped.dequeued()

	buffer.RetryPathlessSends()
	req.Empty(pathlessSeqs(buffer), "a landed send was left awaiting a first send")
	req.Empty(drainRetransmits(buffer), "a landed send was attempted again as a first send")
}

// TestPathlessSetKeepsQueuedPayloads: a payload that cannot be claimed is already
// queued for the sender, so a retry leaves it in place rather than dropping it.
func TestPathlessSetKeepsQueuedPayloads(t *testing.T) {
	req := require.New(t)
	buffer, _ := newFailingSendBuffer(nil)

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)

	// still claimed from the immediate attempt, not yet popped by the sender
	req.False(txp.isRetransmittable())

	buffer.RetryPathlessSends()
	req.Equal([]int32{1}, pathlessSeqs(buffer), "a payload awaiting the sender was dropped from the set")
}

// TestPathlessRetryIsInSequenceOrder: concurrent sends resolve out of order, so a
// retry restores sequence order. The receiver releases payloads strictly in sequence,
// so sending a later one first leaves it buffered until the gap ahead of it is filled.
func TestPathlessRetryIsInSequenceOrder(t *testing.T) {
	req := require.New(t)
	buffer, _ := newFailingSendBuffer(nil)

	for _, seq := range []int32{3, 1, 2} {
		txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: seq})
		buffer.buffer[seq] = txp
		buffer.initialSendCallback(txp)(nil)
		senderFails(buffer)
	}

	buffer.RetryPathlessSends()
	req.Equal([]int32{1, 2, 3}, drainRetransmits(buffer))
}

// TestSentSendDoesNotJoinPathlessSet: a payload a path accepted is in flight, so it
// belongs to the retransmit timer and must not enter the set awaiting a first send.
func TestSentSendDoesNotJoinPathlessSet(t *testing.T) {
	req := require.New(t)
	buffer := newFlushTestBuffer()

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(testPath("a"))

	req.Empty(pathlessSeqs(buffer))
	req.Empty(drainRetransmits(buffer))
	req.NotEqual(int64(math.MaxInt64), txp.getAge(), "a sent payload should carry a send time")
}

// TestClaimForRetransmitIsExclusive: the claim is what keeps two goroutines from both
// pushing one payload onto the retransmit list and corrupting its links.
func TestClaimForRetransmitIsExclusive(t *testing.T) {
	req := require.New(t)
	buffer := newFlushTestBuffer()

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	req.True(txp.claimForRetransmit())
	req.False(txp.claimForRetransmit(), "a queued payload was claimed twice")

	buffer.retransmitPush(txp)
	req.Equal([]int32{1}, drainRetransmits(buffer))

	// an acked payload is never claimable
	acked := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 2})
	acked.markAcked()
	req.False(acked.claimForRetransmit())
}

// TestPathlessFirstSendIsNotFlaggedAsRetransmit: a payload whose first send found
// no path is carried later by the retransmit sender, but that send is still its
// first transmission. It must go out unflagged and uncounted, because the receiver
// meters each payload once on its first non-retransmit arrival, so flagging it would
// exclude it from that count. A genuine retransmit of the same payload afterwards is
// flagged and counted.
func TestPathlessFirstSendIsNotFlaggedAsRetransmit(t *testing.T) {
	req := require.New(t)
	metrics := &retransmitCountingMetrics{}
	adapter := &flagRecordingAdapter{metrics: metrics}
	x := NewXgress("c1", "ctrl", "addr", nil, Initiator, DefaultOptions(), nil)
	x.SetDataPlaneAdapter(adapter)
	buffer := x.payloadBuffer

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil) // no path took it

	// the retransmit sender carries it: still a first transmission
	popped := buffer.retransmitPop()
	req.NotNil(popped)
	buffer.sendQueuedPayload(popped)
	popped.dequeued()

	req.Equal([]bool{false}, adapter.flags, "a pathless first send went out flagged as a retransmit")
	req.False(txp.payload.IsRetransmitFlagSet())
	req.EqualValues(0, metrics.retransmits.Load(), "a pathless first send was counted as a retransmit")
	req.NotEqual(int64(math.MaxInt64), txp.getAge(), "the send should have landed")

	// now that it has been sent, a further send of it is a genuine retransmit
	req.True(txp.claimForRetransmit())
	buffer.sendQueuedPayload(txp)
	txp.dequeued()

	req.Equal([]bool{false, true}, adapter.flags, "a genuine retransmit went out unflagged")
	req.True(txp.payload.IsRetransmitFlagSet())
	req.EqualValues(1, metrics.retransmits.Load())
}

// TestLandedSendLeavesPathlessSetImmediately: the send that lands a payload removes
// it from the set, rather than leaving it for a later retry to prune. A connection
// that recovers and then goes quiet gets no further retry, and acknowledgement drops
// the payload from the send buffer, so the set would otherwise be the sole thing
// pinning the whole recovered window until teardown.
func TestLandedSendLeavesPathlessSetImmediately(t *testing.T) {
	req := require.New(t)
	buffer := newFlushTestBuffer()

	for _, seq := range []int32{1, 2, 3} {
		txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: seq})
		buffer.buffer[seq] = txp
		buffer.initialSendCallback(txp)(nil)
	}
	req.Equal([]int32{1, 2, 3}, pathlessSeqs(buffer))

	// a path arrives and the sender lands every payload
	buffer.RetryPathlessSends()
	for p := buffer.retransmitPop(); p != nil; p = buffer.retransmitPop() {
		buffer.sendQueuedPayload(p)
		p.dequeued()
	}

	req.Empty(pathlessSeqs(buffer), "the recovered window stayed pinned in the pathless set")
}

// TestFailedSendKeepsPathlessMembership: only a landed send releases membership. A
// send that did not land leaves the payload in the set for the next retry.
func TestFailedSendKeepsPathlessMembership(t *testing.T) {
	req := require.New(t)
	buffer, _ := newFailingSendBuffer(nil)

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)

	senderFails(buffer)

	req.Equal([]int32{1}, pathlessSeqs(buffer), "a failed send released membership")
}

// TestRetryDuringActiveSendIsNotLost: a retry can arrive while the payload is
// claimed by a send already in progress. It cannot queue the payload then, and if
// that send fails to land, no further path change may come. The retransmit tick
// sweeps the set, so the payload is dispatched again without depending on a retry
// having landed at a moment it could act.
func TestRetryDuringActiveSendIsNotLost(t *testing.T) {
	req := require.New(t)
	buffer, _ := newFailingSendBuffer(nil)

	txp := buffer.newTxPayload(&Payload{CircuitId: "c1", Sequence: 1})
	buffer.buffer[1] = txp
	buffer.initialSendCallback(txp)(nil)

	// the sender has claimed it and is mid-send
	popped := buffer.retransmitPop()
	req.NotNil(popped)
	req.False(txp.isRetransmittable(), "the send should hold the claim")

	// a path change lands now: it can neither claim nor dispatch the payload
	buffer.RetryPathlessSends()
	req.Nil(buffer.retransmitPop(), "a claimed payload should not be queued twice")
	req.Equal([]int32{1}, pathlessSeqs(buffer), "the payload must stay in the set")

	// that send then fails to land, releasing the claim with nothing queued
	buffer.sendQueuedPayload(popped)
	popped.dequeued()
	req.Nil(buffer.retransmitPop())
	req.EqualValues(math.MaxInt64, txp.getAge(), "still never sent")

	// the sweep is throttled well below the retransmit cadence, so a tick inside
	// its interval must leave the payload alone
	buffer.lastRetransmitTime = 0
	buffer.lastPathlessSweep = time.Now().UnixMilli()
	buffer.retransmit()
	req.Nil(buffer.retransmitPop(), "the sweep ran inside its own interval")

	// once the interval has passed it picks the payload up, with no path change
	buffer.lastPathlessSweep = time.Now().UnixMilli() - pathlessSweepIntervalMs - 1
	buffer.retransmit()

	req.Equal([]int32{1}, drainRetransmits(buffer), "the swept payload was not dispatched")
}
