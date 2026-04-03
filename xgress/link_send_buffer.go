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
	closeWhenEmpty        atomic.Bool
	events                chan sendBufferEvent
	readDeadlineCb        atomic.Pointer[deadlineCallback]
	writeDeadlineCb       atomic.Pointer[deadlineCallback]
	blockedSince          time.Time
	closeStart            time.Time
}

type txPayload struct {
	age        int64
	payload    *Payload
	retxQueued int32
	x          *Xgress
	next       *txPayload
	prev       *txPayload
}

func (self *txPayload) markSent() {
	atomic.StoreInt64(&self.age, time.Now().UnixMilli())
}

func (self *txPayload) getAge() int64 {
	return atomic.LoadInt64(&self.age)
}

func (self *txPayload) markQueued() {
	atomic.AddInt32(&self.retxQueued, 1)
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
	}

	return buffer
}

func (buffer *LinkSendBuffer) CloseWhenEmpty() bool {
	pfxlog.ContextLogger(buffer.x.Label()).Debug("close when empty")
	return buffer.closeWhenEmpty.CompareAndSwap(false, true)
}

func (buffer *LinkSendBuffer) BufferPayload(payload *Payload) (func(), error) {
	txPayload := &txPayload{payload: payload, age: math.MaxInt64, x: buffer.x}

	select {
	case buffer.newlyBuffered <- txPayload:
		pfxlog.ContextLogger(buffer.x.Label()).Debugf("buffered [%d]", payload.GetSequence())
		return txPayload.markSent, nil
	case <-buffer.closeNotify:
		return nil, ErrWriteClosed
	}
}

func (buffer *LinkSendBuffer) BufferPayloadWithDeadline(payload *Payload, ctx context.Context) (func(), error) {
	txPayload := &txPayload{payload: payload, age: math.MaxInt64, x: buffer.x}

	for {
		select {
		case <-ctx.Done():
			return nil, os.ErrDeadlineExceeded
		case buffer.newlyBuffered <- txPayload:
			pfxlog.ContextLogger(buffer.x.Label()).Debugf("buffered [%d]", payload.GetSequence())
			return txPayload.markSent, nil
		case <-buffer.closeNotify:
			return nil, ErrWriteClosed
		}
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
	defer log.Debugf("[%p] exited", buffer)
	defer buffer.drainDeadlines()
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

		rdCb := buffer.readDeadlineCb.Load()
		wrCb := buffer.writeDeadlineCb.Load()

		var rdTimer <-chan time.Time
		var wrTimer <-chan time.Time
		if rdCb != nil {
			rdTimer = rdCb.C
		}
		if wrCb != nil {
			wrTimer = wrCb.C
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

		case <-rdTimer:
			rdCb.fire()

		case <-wrTimer:
			wrCb.fire()

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

// drainDeadlines processes deadline timer callbacks after the send buffer has
// closed but while the xgress is still alive. This handles the half-close case
// where the write path is done but the read adapter still needs deadlines.
func (buffer *LinkSendBuffer) drainDeadlines() {
	for {
		rdCb := buffer.readDeadlineCb.Load()
		wrCb := buffer.writeDeadlineCb.Load()

		var rdTimer <-chan time.Time
		var wrTimer <-chan time.Time
		if rdCb != nil {
			rdTimer = rdCb.C
		}
		if wrCb != nil {
			wrTimer = wrCb.C
		}

		select {
		case <-rdTimer:
			rdCb.fire()
		case <-wrTimer:
			wrCb.fire()
		case event := <-buffer.events:
			event.handle(buffer)
		case <-buffer.x.closeNotify:
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

func (buffer *LinkSendBuffer) retransmit() {
	now := time.Now().UnixMilli()
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
			v.markQueued()
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
	log := pfxlog.ContextLogger(buffer.x.Label())
	for {
		for p := buffer.retransmitPop(); p != nil; p = buffer.retransmitPop() {
			if !p.isAcked() {
				p.payload.MarkAsRetransmit()
				if err := buffer.x.dataPlane.RetransmitPayload(buffer.x.address, p.payload); err != nil {
					if !buffer.IsClosed() {
						log.WithError(err).Errorf("unexpected error while retransmitting payload from [@/%v]", buffer.x.address)
						buffer.metrics().MarkRetransmissionFailure()
					} else {
						log.WithError(err).Tracef("unexpected error while retransmitting payload from [@/%v] (already closed)", buffer.x.address)
					}
				} else {
					p.markSent()
					buffer.metrics().MarkRetransmission()
				}
			}
			p.dequeued()
		}

		select {
		case <-buffer.retransmitNotify:
		case <-buffer.closeNotify:
			return
		}
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

func (buffer *LinkSendBuffer) Inspect() *SendBufferDetail {
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

	result := buffer.inspect()
	result.AcquiredSafely = false
	return result
}

// sendBufferEvent is processed by the LinkSendBuffer run loop. Implementations
// include inspect requests and deadline wake signals.
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

// deadlineWakeEvent is a no-op event that forces the run loop's select to
// re-evaluate, picking up a newly registered deadline timer channel.
type deadlineWakeEvent struct{}

func (deadlineWakeEvent) handle(*LinkSendBuffer) {}
