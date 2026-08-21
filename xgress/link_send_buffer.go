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
	"context"
	"math"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/sirupsen/logrus"
)

// Note: if altering this struct, be sure to account for 64 bit alignment on 32 bit arm arch
// https://pkg.go.dev/sync/atomic#pkg-note-BUG
// https://github.com/golang/go/issues/36606
type LinkSendBuffer struct {
	x                     *Xgress
	buffer                map[int32]*txPayload
	newlyBuffered         chan *txPayload
	newlyReceivedAcks     chan *Acknowledgement
	retxLock              sync.Mutex
	retxHead              *txPayload
	retxTail              *txPayload
	retransmitNotify      chan struct{}
	windowsSize           uint32
	linkSendBufferSize    uint32
	linkRecvBufferSize    uint32
	accumulator           uint32
	successfulAcks        uint32
	duplicateAcks         uint32
	retransmits           uint32
	closeNotify           chan struct{}
	closed                atomic.Bool
	blockedByLocalWindow  bool
	blockedByRemoteWindow bool
	retxScale             float64
	retxThreshold         uint32
	lastRtt               uint16
	lastRetransmitTime    int64
	lastPathlessSweep     int64
	closeWhenEmpty        atomic.Bool
	events                chan sendBufferEvent
	runExited             chan struct{}
	blockedSince          time.Time
	closeStart            time.Time

	// pathless holds the payloads awaiting a first send, which nothing else will
	// revisit: the retransmit timer and the flush both skip payloads that have
	// never been sent. Keyed by sequence, so the send that lands one can remove it
	// directly rather than leaving it pinned here until something sweeps.
	pathlessLock sync.Mutex
	pathless     map[int32]*txPayload
}

type txPayload struct {
	age        int64
	payload    *Payload
	retxQueued int32
	x          *Xgress
	next       *txPayload
	prev       *txPayload
	path       atomic.Pointer[Path]
}

// markSentOn records that the payload was handed to the given transport path,
// updating both the stored path and the send time. A nil path means no live
// path accepted the payload (the no-send contract): the payload is left
// unsent, so it is not treated as in-flight.
func (self *txPayload) markSentOn(path Path) {
	if path == nil {
		return
	}
	self.path.Store(&path)
	atomic.StoreInt64(&self.age, time.Now().UnixMilli())
}

// getPath returns the path this payload was last sent over, or nil if it has
// not been sent.
func (self *txPayload) getPath() Path {
	if t := self.path.Load(); t != nil {
		return *t
	}
	return nil
}

func (self *txPayload) getAge() int64 {
	return atomic.LoadInt64(&self.age)
}

// markAcked marks the payload and acked and returns true if the payload is queued for retransmission
func (self *txPayload) markAcked() bool {
	return atomic.AddInt32(&self.retxQueued, 2) > 2
}

func (self *txPayload) dequeued() {
	atomic.AddInt32(&self.retxQueued, -1)
}

func (self *txPayload) isAcked() bool {
	return atomic.LoadInt32(&self.retxQueued) > 1
}

func (self *txPayload) isRetransmittable() bool {
	return atomic.LoadInt32(&self.retxQueued) == 0
}

// claimForRetransmit reserves the payload for the retransmit list, returning
// false if it is already queued or has been acked. Combining the check and the
// mark into one CAS makes it safe to claim from any goroutine, not only the run
// loop; two concurrent claimants would otherwise both push and corrupt the
// list's links.
func (self *txPayload) claimForRetransmit() bool {
	return atomic.CompareAndSwapInt32(&self.retxQueued, 0, 1)
}

func NewLinkSendBuffer(x *Xgress) *LinkSendBuffer {
	logrus.Debugf("txPortalStartSize = %d, txPortalMinSize = %d",
		x.Options.TxPortalStartSize,
		x.Options.TxPortalMinSize)

	// newlyBuffered should be size 0, otherwise payloads can be sent and acks received before the payload is
	// processed by the LinkSendBuffer
	buffer := &LinkSendBuffer{
		x:                 x,
		buffer:            make(map[int32]*txPayload),
		newlyBuffered:     make(chan *txPayload),
		newlyReceivedAcks: make(chan *Acknowledgement, 4),
		retransmitNotify:  make(chan struct{}, 1),
		closeNotify:       make(chan struct{}),
		windowsSize:       x.Options.TxPortalStartSize,
		retxThreshold:     x.Options.RetxStartMs,
		retxScale:         x.Options.RetxScale,
		events:            make(chan sendBufferEvent, 1),
		runExited:         make(chan struct{}),
		pathless:          make(map[int32]*txPayload),
	}

	return buffer
}

func (buffer *LinkSendBuffer) CloseWhenEmpty() bool {
	pfxlog.ContextLogger(buffer.x.Label()).Debug("close when empty")
	return buffer.closeWhenEmpty.CompareAndSwap(false, true)
}

func (buffer *LinkSendBuffer) BufferPayload(payload *Payload) (func(Path), error) {
	txPayload := buffer.newTxPayload(payload)

	select {
	case buffer.newlyBuffered <- txPayload:
		pfxlog.ContextLogger(buffer.x.Label()).Debugf("buffered [%d]", payload.GetSequence())
		return buffer.initialSendCallback(txPayload), nil
	case <-buffer.closeNotify:
		return nil, ErrWriteClosed
	}
}

func (buffer *LinkSendBuffer) BufferPayloadWithDeadline(payload *Payload, ctx context.Context) (func(Path), error) {
	txPayload := buffer.newTxPayload(payload)

	for {
		select {
		case <-ctx.Done():
			return nil, os.ErrDeadlineExceeded
		case buffer.newlyBuffered <- txPayload:
			pfxlog.ContextLogger(buffer.x.Label()).Debugf("buffered [%d]", payload.GetSequence())
			return buffer.initialSendCallback(txPayload), nil
		case <-buffer.closeNotify:
			return nil, ErrWriteClosed
		}
	}
}

// newTxPayload wraps a payload for buffering. Its age stays at the initial max
// until a send actually carries it, which is what marks it never-sent.
func (buffer *LinkSendBuffer) newTxPayload(payload *Payload) *txPayload {
	return &txPayload{
		payload: payload,
		age:     math.MaxInt64,
		x:       buffer.x,
	}
}

// initialSendCallback returns the callback the caller invokes with the outcome of
// the payload's first transmit attempt.
//
// A nil path means no live transport took the payload, so it is still unsent and
// nothing else will pick it up: the retransmit timer and the flush both skip
// payloads that have never been sent. The payload therefore joins the set awaiting
// a first send, and stays there until one lands.
func (buffer *LinkSendBuffer) initialSendCallback(txPayload *txPayload) func(Path) {
	return func(path Path) {
		if path != nil {
			txPayload.markSentOn(path)
			return
		}

		buffer.pathlessLock.Lock()
		buffer.pathless[txPayload.payload.Sequence] = txPayload
		buffer.pathlessLock.Unlock()

		// One immediate attempt, which is what carries the payload when a path
		// arrived while this send was in flight. Failure needs no handling: the
		// payload is already in the set, so the next path change retries it.
		if txPayload.claimForRetransmit() {
			buffer.retransmitPush(txPayload)
		}
	}
}

// OnPathAvailable resumes flow after a pathless gap: it retries the sends that
// found no path, and flushes the rest of the window so payloads already in flight
// move to the new path rather than waiting out the retransmit threshold.
func (buffer *LinkSendBuffer) OnPathAvailable() {
	// Stamped before anything is handed to the sender, so every send this
	// resumption causes is recognized as current by the flush rather than being
	// mistaken for a payload stranded on the lost path.
	requestedAt := time.Now().UnixMilli()

	buffer.RetryPathlessSends()
	buffer.flush(requestedAt)
}

// RetryPathlessSends attempts every payload still awaiting a first send, in
// sequence order, and drops the ones that no longer need one. It is called when
// the set of usable paths changes, which is the only thing that can turn a failed
// first send into a deliverable one: such a send failed either because no path was
// selectable or because the selected path's channel had closed, so retrying
// against an unchanged path set would fail identically.
//
// A payload is kept until a send lands. One that cannot be claimed is already
// queued for the sender, so it is left in place rather than dropped. One that no
// longer needs a first send is removed: normally by the send that landed it, and
// here as a backstop for a payload acked or finished while queued.
func (buffer *LinkSendBuffer) RetryPathlessSends() {
	buffer.pathlessLock.Lock()
	defer buffer.pathlessLock.Unlock()

	awaiting := make([]*txPayload, 0, len(buffer.pathless))
	for seq, p := range buffer.pathless {
		if p.getAge() != math.MaxInt64 || p.isAcked() {
			delete(buffer.pathless, seq)
			continue
		}
		awaiting = append(awaiting, p)
	}

	// dispatched in sequence order: the receiver releases payloads strictly in
	// sequence, so sending a later one first leaves it buffered on the far side
	// until the gap ahead of it is filled
	slices.SortFunc(awaiting, func(a, b *txPayload) int {
		return int(a.payload.Sequence - b.payload.Sequence)
	})
	for _, p := range awaiting {
		if p.claimForRetransmit() {
			buffer.retransmitPush(p)
		}
	}
}

// removePathless drops a payload from the set awaiting a first send, called by the
// send that landed it. Without this the set pins the whole pathless window until
// something else sweeps it, which for a connection that recovers and then goes
// quiet may not happen before teardown.
func (buffer *LinkSendBuffer) removePathless(p *txPayload) {
	buffer.pathlessLock.Lock()
	delete(buffer.pathless, p.payload.Sequence)
	buffer.pathlessLock.Unlock()
}

// flush asks the run loop to re-dispatch payloads that were in flight when the
// path carrying them was lost, so a circuit resuming on a new path does not wait
// out the retransmit threshold first.
//
// requestedAt must be captured before any payload is handed to the sender as part
// of the same resumption, so that sends completing on the new path while this
// request is queued are recognized as current and left alone. Re-dispatch is
// idempotent: a payload already queued for retransmit is skipped.
func (buffer *LinkSendBuffer) flush(requestedAt int64) {
	select {
	case buffer.events <- sendBufferFlushEvent{requestedAt: requestedAt}:
	case <-buffer.closeNotify:
	}
}

func (buffer *LinkSendBuffer) ReceiveAcknowledgement(ack *Acknowledgement) {
	log := pfxlog.ContextLogger(buffer.x.Label()).WithFields(ack.GetLoggerFields())
	log.Debug("ack received")
	select {
	case buffer.newlyReceivedAcks <- ack:
		log.Debug("ack processed")
	case <-buffer.closeNotify:
		// if end of circuit was received, we've cleanly shutdown and can ignore any trailing acks
		if buffer.x.IsEndOfCircuitReceived() {
			log.Debug("payload buffer closed")
		} else {
			log.Error("payload buffer closed")
		}
	}
}

func (buffer *LinkSendBuffer) metrics() Metrics {
	return buffer.x.dataPlane.GetMetrics()
}

func (buffer *LinkSendBuffer) Close() {
	if buffer.closed.CompareAndSwap(false, true) {
		pfxlog.ContextLogger(buffer.x.Label()).Debugf("[%p] closing", buffer)
		close(buffer.closeNotify)
	}
	buffer.x.closeIfRxAndTxDone()
}

func (buffer *LinkSendBuffer) IsClosed() bool {
	return buffer.closed.Load()
}

func (buffer *LinkSendBuffer) isBlocked() bool {
	wasBlocked := buffer.blockedByLocalWindow || buffer.blockedByRemoteWindow
	blocked := false

	if buffer.x.Options.TxPortalMaxSize < buffer.linkRecvBufferSize {
		blocked = true
		if !buffer.blockedByRemoteWindow {
			buffer.blockedByRemoteWindow = true
			buffer.metrics().BufferBlockedByRemoteWindow()
		}
	} else if buffer.blockedByRemoteWindow {
		buffer.blockedByRemoteWindow = false
		buffer.metrics().BufferUnblockedByRemoteWindow()
	}

	if buffer.windowsSize < buffer.linkSendBufferSize {
		blocked = true
		if !buffer.blockedByLocalWindow {
			buffer.blockedByLocalWindow = true
			buffer.metrics().BufferBlockedByLocalWindow()
		}
	} else if buffer.blockedByLocalWindow {
		buffer.blockedByLocalWindow = false
		buffer.metrics().BufferUnblockedByLocalWindow()
	}

	if blocked {
		if !wasBlocked {
			buffer.blockedSince = time.Now()
		}
		pfxlog.ContextLogger(buffer.x.Label()).Debugf("blocked=%v win_size=%v tx_buffer_size=%v rx_buffer_size=%v", blocked, buffer.windowsSize, buffer.linkSendBufferSize, buffer.linkRecvBufferSize)
	} else if wasBlocked {
		buffer.metrics().BufferUnblocked(time.Since(buffer.blockedSince))
	}

	return blocked
}

func (buffer *LinkSendBuffer) run() {
	log := pfxlog.ContextLogger(buffer.x.Label())
	// Registered first so it runs last: once this closes, no goroutine mutates the
	// fields Inspect reads.
	defer close(buffer.runExited)
	defer log.Debugf("[%p] exited", buffer)
	log.Debugf("[%p] started", buffer)

	go buffer.retransmitSender()

	var buffered chan *txPayload

	retransmitTicker := time.NewTicker(100 * time.Millisecond)
	defer retransmitTicker.Stop()

	for {
		// bias acks, process all pending, since that should not block
		select {
		case ack := <-buffer.newlyReceivedAcks:
			buffer.receiveAcknowledgement(ack)
		case <-buffer.closeNotify:
			buffer.cleanupMetrics()
			return
		default:
		}

		// don't block when we're closing, since the only thing that should still be coming in is end-of-circuit
		// if we're blocked, but empty, let one payload in to reduce the chances of a stall
		if buffer.isBlocked() && !buffer.closeWhenEmpty.Load() && buffer.linkSendBufferSize != 0 {
			buffered = nil
		} else {
			buffered = buffer.newlyBuffered

			select {
			case txPayload := <-buffered:
				buffer.buffer[txPayload.payload.GetSequence()] = txPayload
				payloadSize := len(txPayload.payload.Data)
				buffer.linkSendBufferSize += uint32(payloadSize)
				buffer.metrics().SendPayloadBuffered(int64(payloadSize))
				log.Tracef("buffering payload %v with size %v. payload buffer size: %v",
					txPayload.payload.Sequence, len(txPayload.payload.Data), buffer.linkSendBufferSize)
			case <-buffer.closeNotify:
				buffer.cleanupMetrics()
				return
			default:
			}
		}

		select {
		case event := <-buffer.events:
			event.handle(buffer)

		case ack := <-buffer.newlyReceivedAcks:
			buffer.receiveAcknowledgement(ack)
			buffer.retransmit()
			buffer.checkForClose()

		case txPayload := <-buffered:
			buffer.buffer[txPayload.payload.GetSequence()] = txPayload
			payloadSize := len(txPayload.payload.Data)
			buffer.linkSendBufferSize += uint32(payloadSize)
			buffer.metrics().SendPayloadBuffered(int64(payloadSize))
			log.Tracef("buffering payload %v with size %v. payload buffer size: %v",
				txPayload.payload.Sequence, len(txPayload.payload.Data), buffer.linkSendBufferSize)

		case <-retransmitTicker.C:
			buffer.retransmit()
			buffer.checkForClose()

		case <-buffer.closeNotify:
			buffer.cleanupMetrics()
			if len(buffer.buffer) > 0 {
				isCircuitEnd := false
				if len(buffer.buffer) == 1 {
					for _, p := range buffer.buffer {
						isCircuitEnd = p.payload.IsCircuitEndFlagSet() || p.payload.IsFlagEOFSet()
					}
				}
				if !isCircuitEnd {
					log.WithField("payloadCount", len(buffer.buffer)).Warn("closing while buffer contains unacked payloads")
				}
			}
			return
		}
	}
}

func (buffer *LinkSendBuffer) checkForClose() {
	if buffer.closeWhenEmpty.Load() {
		if buffer.closeStart.IsZero() {
			buffer.closeStart = time.Now()
		}
		closeDuration := time.Since(buffer.closeStart)

		if (len(buffer.buffer) == 0 && closeDuration > 5*time.Second) || closeDuration > buffer.x.Options.MaxCloseWait {
			buffer.Close()
		} else if len(buffer.buffer) == 1 && closeDuration > 5*time.Second {
			for _, p := range buffer.buffer {
				if p.payload.IsCircuitEndFlagSet() || p.payload.IsFlagEOFSet() {
					buffer.Close()
				}
			}
		}
	}
}

func (buffer *LinkSendBuffer) cleanupMetrics() {
	if buffer.blockedByLocalWindow {
		buffer.metrics().BufferUnblockedByLocalWindow()
	}
	if buffer.blockedByRemoteWindow {
		buffer.metrics().BufferUnblockedByRemoteWindow()
	}
}

func (buffer *LinkSendBuffer) receiveAcknowledgement(ack *Acknowledgement) {
	log := pfxlog.ContextLogger(buffer.x.Label()).WithFields(ack.GetLoggerFields())

	for _, sequence := range ack.Sequence {
		if txPayload, found := buffer.buffer[sequence]; found {
			txPayload.markAcked()

			payloadSize := uint32(len(txPayload.payload.Data))
			buffer.accumulator += payloadSize
			buffer.successfulAcks++
			delete(buffer.buffer, sequence)
			buffer.metrics().SendPayloadDelivered(int64(payloadSize))
			buffer.linkSendBufferSize -= payloadSize
			log.Debugf("removing payload %v with size %v. payload buffer size: %v",
				txPayload.payload.Sequence, len(txPayload.payload.Data), buffer.linkSendBufferSize)

			if buffer.successfulAcks >= buffer.x.Options.TxPortalIncreaseThresh {
				buffer.successfulAcks = 0
				delta := uint32(float64(buffer.accumulator) * buffer.x.Options.TxPortalIncreaseScale)
				buffer.windowsSize += delta
				if buffer.windowsSize > buffer.x.Options.TxPortalMaxSize {
					buffer.windowsSize = buffer.x.Options.TxPortalMaxSize
				}
				buffer.retxScale -= 0.01
				if buffer.retxScale < buffer.x.Options.RetxScale {
					buffer.retxScale = buffer.x.Options.RetxScale
				}
			}
		} else { // duplicate ack
			buffer.metrics().MarkDuplicateAck()
			buffer.duplicateAcks++
			if buffer.duplicateAcks >= buffer.x.Options.TxPortalDupAckThresh {
				buffer.duplicateAcks = 0
				buffer.retxScale += 0.2
			}
		}
	}

	buffer.linkRecvBufferSize = ack.RecvBufferSize
	if ack.RTT > 0 {
		rtt := uint16(time.Now().UnixMilli()) - ack.RTT

		// Per-path RTT: attribute the raw round-trip sample to the path the ack
		// arrived on (not the stored send path), since arrival affinity routes
		// each ack back over the path its payload traveled. This runs for every
		// nonzero-RTT ack, including duplicate acks, so when both copies of a
		// cross-path retransmit arrive each path gets its own sample; only the
		// first ack mutated delivery/loss state above.
		if p := ack.ArrivalPath(); p != nil {
			p.RecordRtt(rtt)
		}

		// Cap RTT growth rate — a single sample can move at most MaxRttScale * lastRtt.
		// MaxRttScale == 0 disables the cap.
		if buffer.lastRtt > 0 && buffer.x.Options.MaxRttScale > 0 {
			maxRtt := buffer.lastRtt * buffer.x.Options.MaxRttScale
			if rtt > maxRtt {
				rtt = maxRtt
			}
		}

		if buffer.lastRtt > 0 {
			rtt = (rtt + buffer.lastRtt) >> 1
		}
		buffer.lastRtt = rtt
		buffer.retxThreshold = uint32(float64(rtt)*buffer.retxScale) + buffer.x.Options.RetxAddMs
		if buffer.x.Options.RetxMaxMs > 0 && buffer.retxThreshold > buffer.x.Options.RetxMaxMs {
			buffer.retxThreshold = buffer.x.Options.RetxMaxMs
		}
	}
}

// pathlessSweepIntervalMs is how often the payloads awaiting a first send are
// re-attempted absent a path change. Well clear of the default 200ms retransmit
// threshold, so the sweep is recognisable as a backstop rather than part of the
// retransmit cadence.
const pathlessSweepIntervalMs = 1000

func (buffer *LinkSendBuffer) retransmit() {
	now := time.Now().UnixMilli()

	// Backstop for a retry absorbed by an in-flight send: a path change can arrive
	// while a payload is claimed, so the retry cannot queue it, and if that send
	// then fails to land nothing else would dispatch it again. Path changes retry
	// immediately, so this only has to bound how long a missed retry goes
	// unnoticed. It is deliberately far slower than the retransmit cadence: every
	// sweep re-attempts the whole set, and while a circuit is genuinely pathless
	// every one of those attempts is known to fail.
	if now-buffer.lastPathlessSweep > pathlessSweepIntervalMs {
		buffer.lastPathlessSweep = now
		buffer.RetryPathlessSends()
	}

	if len(buffer.buffer) > 0 && (now-buffer.lastRetransmitTime) > 64 {
		log := pfxlog.ContextLogger(buffer.x.Label())

		retransmitted := 0
		var rtxList []*txPayload
		for _, v := range buffer.buffer {
			age := v.getAge()
			if age != math.MaxInt64 && v.isRetransmittable() && uint32(now-age) >= buffer.retxThreshold {
				rtxList = append(rtxList, v)
			}
		}

		slices.SortFunc(rtxList, func(a, b *txPayload) int {
			return int(a.payload.Sequence - b.payload.Sequence)
		})

		for _, v := range rtxList {
			if !v.claimForRetransmit() {
				continue
			}
			// Per-path loss: charge the path the payload was last sent on. The
			// stored tag still points there (it advances only when a retransmit
			// is accepted on a new path), and rtxList excludes never-sent
			// payloads, so the tag is non-nil here.
			if p := v.getPath(); p != nil {
				p.RecordLoss()
			}
			buffer.retransmitPush(v)
			retransmitted++
			buffer.retransmits++
			if buffer.retransmits >= buffer.x.Options.TxPortalRetxThresh {
				buffer.accumulator = 0
				buffer.retransmits = 0
				buffer.scale(buffer.x.Options.TxPortalRetxScale)
			}
		}

		if retransmitted > 0 {
			log.WithField("circuitId", buffer.x.circuitId).Debugf("retransmitted [%d] payloads, [%d] buffered, linkSendBufferSize: %d", retransmitted, len(buffer.buffer), buffer.linkSendBufferSize)
		}
		buffer.lastRetransmitTime = now
	}
}

// retransmitPush adds a payload to the retransmit list and notifies the sender goroutine.
// Called from run() via retransmit(). Always succeeds — the list is bounded by the send window.
func (buffer *LinkSendBuffer) retransmitPush(p *txPayload) {
	buffer.retxLock.Lock()
	if buffer.retxHead == nil {
		buffer.retxHead = p
		buffer.retxTail = p
	} else {
		p.next = buffer.retxTail
		buffer.retxTail.prev = p
		buffer.retxTail = p
	}
	buffer.retxLock.Unlock()

	select {
	case buffer.retransmitNotify <- struct{}{}:
	default:
	}
}

// retransmitPop removes and returns the head of the retransmit list, or nil if empty.
func (buffer *LinkSendBuffer) retransmitPop() *txPayload {
	buffer.retxLock.Lock()
	defer buffer.retxLock.Unlock()

	result := buffer.retxHead
	if result == nil {
		return nil
	}

	if result.prev == nil {
		buffer.retxHead = nil
		buffer.retxTail = nil
	} else {
		buffer.retxHead = result.prev
		result.prev.next = nil
	}
	result.prev = nil
	result.next = nil
	return result
}

// retransmitSender processes the retransmit list using blocking sends. Each LinkSendBuffer
// gets its own goroutine so one slow xgress can't stall others.
func (buffer *LinkSendBuffer) retransmitSender() {
	for {
		for p := buffer.retransmitPop(); p != nil; p = buffer.retransmitPop() {
			buffer.sendQueuedPayload(p)
			p.dequeued()
		}

		select {
		case <-buffer.retransmitNotify:
		case <-buffer.closeNotify:
			return
		}
	}
}

// sendQueuedPayload sends one payload popped from the retransmit list. The list
// carries two kinds of payload: genuine retransmits of already-sent payloads
// (queued by the retransmit timer), and never-sent payloads dispatched out of the
// pathless set (age still at its initial max). A never-sent payload's send here is
// its FIRST transmission, so it must not be marked PayloadFlagRetransmit nor
// counted as a retransmit: the receiver meters each payload once, on its first
// non-retransmit arrival, and flagging a first send would exclude it from that
// count and undercount usage. Only genuine retransmits are flagged/counted.
//
// A send that does not land needs no handling here. A retransmit keeps its send
// time, so the retransmit timer revisits it; a first send is still in the pathless
// set, so the next path change retries it.
func (buffer *LinkSendBuffer) sendQueuedPayload(p *txPayload) {
	if p.isAcked() {
		return
	}
	log := pfxlog.ContextLogger(buffer.x.Label())

	retransmit := p.getAge() != math.MaxInt64
	if retransmit {
		p.payload.MarkAsRetransmit()
	}

	newTag, err := buffer.x.dataPlane.RetransmitPayload(p.getPath(), buffer.x.address, p.payload)
	if err != nil {
		if !buffer.IsClosed() {
			log.WithError(err).Errorf("unexpected error while sending payload from [@/%v]", buffer.x.address)
			if retransmit {
				buffer.metrics().MarkRetransmissionFailure()
			}
		} else {
			log.WithError(err).Tracef("unexpected error while sending payload from [@/%v] (already closed)", buffer.x.address)
		}
		return
	}
	if newTag == nil {
		// no live path took it, so the payload is unchanged and still eligible
		return
	}

	// the send was accepted on a (possibly different) path: advance the stored
	// tag and send time
	p.markSentOn(newTag)
	if retransmit {
		buffer.metrics().MarkRetransmission()
	} else {
		// a first send landed, so the payload no longer awaits one
		buffer.removePathless(p)
	}
}

func (buffer *LinkSendBuffer) scale(factor float64) {
	buffer.windowsSize = uint32(float64(buffer.windowsSize) * factor)
	if factor > 1 {
		if buffer.windowsSize > buffer.x.Options.TxPortalMaxSize {
			buffer.windowsSize = buffer.x.Options.TxPortalMaxSize
		}
	} else if buffer.windowsSize < buffer.x.Options.TxPortalMinSize {
		buffer.windowsSize = buffer.x.Options.TxPortalMinSize
	}
}

func (buffer *LinkSendBuffer) inspect() *SendBufferDetail {
	timeSinceLastRetransmit := time.Duration(time.Now().UnixMilli()-buffer.lastRetransmitTime) * time.Millisecond
	result := &SendBufferDetail{
		WindowSize:            buffer.windowsSize,
		QueuedPayloadCount:    len(buffer.buffer),
		LinkSendBufferSize:    buffer.linkSendBufferSize,
		LinkRecvBufferSize:    buffer.linkRecvBufferSize,
		Accumulator:           buffer.accumulator,
		SuccessfulAcks:        buffer.successfulAcks,
		DuplicateAcks:         buffer.duplicateAcks,
		Retransmits:           buffer.retransmits,
		Closed:                buffer.closed.Load(),
		BlockedByLocalWindow:  buffer.blockedByLocalWindow,
		BlockedByRemoteWindow: buffer.blockedByRemoteWindow,
		RetxScale:             buffer.retxScale,
		RetxThreshold:         buffer.retxThreshold,
		TimeSinceLastRetx:     timeSinceLastRetransmit.String(),
		CloseWhenEmpty:        buffer.closeWhenEmpty.Load(),
	}
	return result
}

// Inspect returns a snapshot of the send buffer's state. It normally hands the request to
// the run loop so the fields are read from the goroutine that owns them. Once the run loop
// has exited there is nobody to service that request and nobody left to mutate the fields,
// so the snapshot is taken directly.
func (buffer *LinkSendBuffer) Inspect() *SendBufferDetail {
	select {
	case <-buffer.runExited:
		result := buffer.inspect()
		result.AcquiredSafely = true
		return result
	default:
	}

	timeout := time.After(100 * time.Millisecond)
	inspectEvent := &sendBufferInspectEvent{
		notifyComplete: make(chan *SendBufferDetail, 1),
	}

	select {
	case buffer.events <- inspectEvent:
		select {
		case result := <-inspectEvent.notifyComplete:
			result.AcquiredSafely = true
			return result
		case <-timeout:
		}
	case <-timeout:
	}

	// The run loop is alive but didn't answer in time, so the snapshot below is read
	// without synchronization and may be inconsistent.
	pfxlog.ContextLogger(buffer.x.Label()).Debug("send buffer inspect timed out, reporting unsynchronized state")

	result := buffer.inspect()
	result.AcquiredSafely = false
	return result
}

// sendBufferEvent is processed by the LinkSendBuffer run loop, which owns the
// buffer map and window state. Implementations include inspect requests and
// flush requests.
type sendBufferEvent interface {
	handle(buffer *LinkSendBuffer)
}

type sendBufferInspectEvent struct {
	notifyComplete chan *SendBufferDetail
}

func (self *sendBufferInspectEvent) handle(buffer *LinkSendBuffer) {
	result := buffer.inspect()
	self.notifyComplete <- result
}

// sendBufferFlushEvent re-queues payloads that were in flight when the path
// carrying them was lost, in sequence order, so a circuit resuming on a new path
// does not wait out the retransmit threshold first. Handled in the run loop so
// it has exclusive access to the buffer map.
//
// requestedAt bounds it to payloads sent before the flush was asked for. The
// request is handed to the run loop asynchronously, so by the time it is handled
// the sender may already have carried payloads over the new path: the pathless
// queue drained into it, or a first send resolved onto it. Those are current, not
// stranded, and re-sending them would put a redundant copy on the wire and count
// a retransmit that never happened. A payload sent within the same millisecond as
// the request is treated as current, since erring that way costs at most one
// payload waiting out the retransmit threshold, while erring the other way
// duplicates it.
//
// Never-sent payloads are excluded for free: their age is still at the initial
// max, which no request timestamp can precede. Their first send belongs to the
// pathless queue, the only place that knows whether one is still in flight.
type sendBufferFlushEvent struct {
	// requestedAt is a UnixMilli timestamp, comparable to txPayload.age.
	requestedAt int64
}

func (self sendBufferFlushEvent) handle(buffer *LinkSendBuffer) {
	var list []*txPayload
	for _, v := range buffer.buffer {
		if v.getAge() < self.requestedAt && v.isRetransmittable() {
			list = append(list, v)
		}
	}
	slices.SortFunc(list, func(a, b *txPayload) int {
		return int(a.payload.Sequence - b.payload.Sequence)
	})
	for _, v := range list {
		if v.claimForRetransmit() {
			buffer.retransmitPush(v)
		}
	}
}
