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
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

var _ xgress.DataPlaneAdapter = (*MultiPathAdapter)(nil)
var _ xgress.CloseHandler = (*MultiPathAdapter)(nil)

// pathLossOutcome is the result of removing a path: it tells the caller
// whether the xgress can continue, is being held open for recovery, or must
// be torn down.
type pathLossOutcome int

const (
	// pathsRemain means other paths still carry the xgress; nothing to do.
	pathsRemain pathLossOutcome = iota
	// holdingForRecovery means the last path was removed but the conn is
	// recoverable, so the xgress is held open and a bounded hold timer is armed.
	holdingForRecovery
	// closeXgress means the last path was removed and the conn is not
	// recoverable, so the xgress must be torn down (today's behavior).
	closeXgress
)

// MultiPathAdapter connects a conn's xgress to the data plane. It implements
// xgress.DataPlaneAdapter over a set of Paths: outbound dispatch consults a
// PathSelector, and the tag returned for each send identifies the carrying
// path so the send buffer can track in-flight payloads per path. It holds
// only circuit-scoped state itself; all transport-specific state lives on
// the paths.
//
// It also owns the pathless policy: when the last path is removed, a
// recoverable conn's xgress is held open for a bounded window instead of
// being closed, so feature code (rerouting takeover, p2p fallback) can attach
// a replacement path.
type MultiPathAdapter struct {
	lock      sync.Mutex
	paths     atomic.Pointer[[]Path]
	selector  PathSelector
	circuitId string
	env       xgress.Env
	xg        *xgress.Xgress

	// pathless-hold state, guarded by lock
	recoverable bool
	holdTimeout time.Duration
	holdTimer   *time.Timer
	holdEpoch   uint64

	// closed stops AddPath attaching a path to an xgress that is going away. The
	// write and AddPath's read both happen under lock, each in the same
	// acquisition as the decision it belongs to, so no path is accepted after a
	// teardown has been decided but before it runs.
	closed bool

	// conn is the owning connection. The adapter uses it to mark the conn
	// closed when the xgress closes, and to actively tear it down on
	// close-on-pathless or hold expiry. Set by the owning conn after construction.
	conn *edgeConnXgress
}

// NewMultiPathAdapter creates an adapter for the given circuit, seeded with
// the given initial path.
func NewMultiPathAdapter(circuitId string, env xgress.Env, selector PathSelector, initial Path) *MultiPathAdapter {
	result := &MultiPathAdapter{
		selector:  selector,
		circuitId: circuitId,
		env:       env,
	}
	paths := []Path{initial}
	result.paths.Store(&paths)
	return result
}

// Paths returns a snapshot of the paths attached to this adapter.
func (self *MultiPathAdapter) Paths() []Path {
	return *self.paths.Load()
}

// AddPath attaches a path to this adapter and reports whether it was accepted.
// The caller is responsible for having registered the path's receive sink first,
// so inbound traffic on the new path has somewhere to land before outbound
// dispatch can select it.
//
// Adding a path cancels any in-progress pathless hold. If the adapter was
// pathless, the buffered send window is flushed over the new path, since
// payloads written during the gap were buffered but never sent.
//
// A path offered after the xgress has begun tearing down is rejected and closed
// here rather than attached: teardown has already taken its snapshot of paths to
// release, so attaching would leave the path registered in its mux, feeding a
// closed xgress. Callers must treat false as the path having been discarded.
func (self *MultiPathAdapter) AddPath(path Path) bool {
	self.lock.Lock()
	if self.closed {
		self.lock.Unlock()
		pfxlog.Logger().WithField("circuitId", self.circuitId).
			Info("path added after xgress teardown began, discarding it")
		if err := path.Close(); err != nil {
			pfxlog.Logger().WithField("circuitId", self.circuitId).WithError(err).
				Error("failed to close late-added path")
		}
		return false
	}
	current := *self.paths.Load()
	wasPathless := len(current) == 0
	updated := make([]Path, 0, len(current)+1)
	updated = append(updated, current...)
	updated = append(updated, path)
	self.paths.Store(&updated)
	self.cancelHoldLocked()
	self.lock.Unlock()

	if wasPathless {
		self.xg.OnPathAvailable()
	} else {
		// paths were already attached, so this is an additional route rather than
		// a resumption: no window re-send, but a first send that previously found
		// nowhere to go may be deliverable over it
		self.xg.OnPathSetChanged()
	}
	return true
}

// RemovePath detaches a path from this adapter and reports whether the xgress
// can continue. It does not close the path; that remains the caller's
// responsibility. When the removal empties the path set, a recoverable conn's
// xgress is held open (a bounded timer is armed) and holdingForRecovery is
// returned; otherwise closeXgress is returned and the caller must tear down.
func (self *MultiPathAdapter) RemovePath(path Path) pathLossOutcome {
	self.lock.Lock()
	current := *self.paths.Load()
	updated := make([]Path, 0, len(current))
	for _, p := range current {
		if p != path {
			updated = append(updated, p)
		}
	}
	self.paths.Store(&updated)

	outcome := pathsRemain
	if len(updated) == 0 {
		if self.recoverable {
			self.armHoldLocked()
			outcome = holdingForRecovery
		} else {
			self.closed = true
			outcome = closeXgress
		}
	}
	self.lock.Unlock()

	// Losing one of several paths is a chance to retry sends that failed against
	// the path just removed. Losing the last one needs no notification: there is
	// nothing left to retry against, and a send that finds no path keeps itself in
	// the pathless set until a path returns.
	if outcome == pathsRemain {
		self.xg.OnPathSetChanged()
	}

	return outcome
}

// SetRecoverable marks the conn recoverable: losing the last path holds the
// xgress open for up to timeout instead of closing it.
func (self *MultiPathAdapter) SetRecoverable(timeout time.Duration) {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.recoverable = true
	self.holdTimeout = timeout
}

// ClearRecoverable removes the recoverable mark and cancels any in-progress
// hold. If the adapter is already pathless, clearing recoverability would
// otherwise leak the connection: the hold timer that would have closed it is
// cancelled and no path will arrive, so the xgress is torn down instead. With a
// path still attached (recovery succeeded, or an ordinary live conn) it just
// clears the flag.
func (self *MultiPathAdapter) ClearRecoverable() {
	self.lock.Lock()
	self.recoverable = false
	self.cancelHoldLocked()
	pathless := len(*self.paths.Load()) == 0
	if pathless {
		self.closed = true
	}
	self.lock.Unlock()

	if pathless {
		self.conn.closeOnPathless()
	}
}

// armHoldLocked starts (or restarts) the bounded pathless-hold timer. The
// epoch lets a fired timer detect that it has been superseded by a later
// AddPath/ClearRecoverable/re-arm. Caller must hold the lock.
func (self *MultiPathAdapter) armHoldLocked() {
	self.holdEpoch++
	epoch := self.holdEpoch
	if self.holdTimer != nil {
		self.holdTimer.Stop()
	}
	self.holdTimer = time.AfterFunc(self.holdTimeout, func() {
		self.onHoldExpired(epoch)
	})
}

// cancelHoldLocked stops the hold timer and invalidates any pending expiry.
// Caller must hold the lock.
func (self *MultiPathAdapter) cancelHoldLocked() {
	self.holdEpoch++
	if self.holdTimer != nil {
		self.holdTimer.Stop()
		self.holdTimer = nil
	}
}

// onHoldExpired closes the xgress if the hold it was armed for is still the
// current one and the adapter is still pathless. A timer that has been
// superseded (a path arrived, recovery was cleared, or the xgress already
// closed) is a no-op.
func (self *MultiPathAdapter) onHoldExpired(epoch uint64) {
	self.lock.Lock()
	stale := epoch != self.holdEpoch || len(*self.paths.Load()) > 0
	if !stale {
		self.closed = true
	}
	self.lock.Unlock()
	if stale {
		return
	}
	pfxlog.Logger().WithField("circuitId", self.circuitId).
		Info("recoverable hold expired with no path attached, closing xgress")
	self.conn.closeOnPathless()
}

// containsPath reports whether the given path is currently attached.
func (self *MultiPathAdapter) containsPath(path Path) bool {
	return slices.Contains(self.Paths(), path)
}

// --- xgress.DataPlaneAdapter implementation ---

func (self *MultiPathAdapter) ForwardPayload(payload *xgress.Payload, _ *xgress.Xgress, ctx context.Context) xgress.Path {
	path := self.selector.SelectForPayload(self.Paths(), payload)
	if path == nil {
		// no path available: the nil tag tells the send buffer to leave the
		// payload unsent rather than marking it in-flight
		return nil
	}
	if err := path.ForwardPayload(payload, ctx); err != nil {
		// the payload was handed to a live transport; recovery happens via
		// retransmission, so it still counts as sent on this path
		pfxlog.Logger().WithField("circuitId", payload.CircuitId).WithError(err).Error("failed to send payload")
	}
	return path
}

func (self *MultiPathAdapter) RetransmitPayload(previous xgress.Path, srcAddr xgress.Address, payload *xgress.Payload) (xgress.Path, error) {
	path := self.selector.SelectForRetransmit(self.Paths(), payload, previous)
	if path == nil {
		// no path available: nil tag, no error. The payload stays buffered and
		// retransmit-eligible.
		return nil, nil
	}
	if err := path.RetransmitPayload(srcAddr, payload); err != nil {
		// the retransmit failed on this path; report it. A dead transport is
		// torn down via its path-loss signal (HandleMuxClose -> RemovePath),
		// which applies the pathless policy, so we do not close the xgress here.
		return nil, err
	}
	return path, nil
}

func (self *MultiPathAdapter) ForwardControlMessage(control *xgress.Control, x *xgress.Xgress) {
	path := self.selector.Primary(self.Paths())
	if path == nil {
		pfxlog.Logger().WithField("circuitId", self.circuitId).Error("no path available to forward control message")
		return
	}
	if err := path.ForwardControlMessage(control); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to forward control message")
	}
}

// ForwardAcknowledgement sends the ack over the path the acknowledged payload
// arrived on (arrival affinity), falling back to the selector's primary path
// when no arrival path is supplied or it is no longer attached and live.
// Arrival affinity keeps per-path RTT samples clean: the ack returns on the
// path the payload traveled, so the round trip measures one path.
func (self *MultiPathAdapter) ForwardAcknowledgement(ack *xgress.Acknowledgement, address xgress.Address, arrival xgress.Path) {
	var path Path
	if arrivalPath, ok := arrival.(Path); ok && self.containsPath(arrivalPath) && !arrivalPath.IsClosed() {
		path = arrivalPath
	} else {
		path = self.selector.Primary(self.Paths())
	}
	if path == nil {
		pfxlog.Logger().WithField("circuitId", self.circuitId).Error("no path available to send acknowledgement")
		return
	}
	if err := path.ForwardAcknowledgement(ack, address); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send acknowledgement")
	}
}

func (self *MultiPathAdapter) GetPayloadIngester() *xgress.PayloadIngester {
	return self.env.GetPayloadIngester()
}

func (self *MultiPathAdapter) GetMetrics() xgress.Metrics {
	return self.env.GetMetrics()
}

// --- xgress.CloseHandler implementation ---

// HandleXgressClose performs circuit-scoped teardown: it notifies the
// controller that the circuit is done, via a live controller-capable path
// when one is available, then releases every path's transport resources.
// Any in-progress pathless hold is cancelled, since the xgress is closing.
func (self *MultiPathAdapter) HandleXgressClose(x *xgress.Xgress) {
	// the circuit is done: clear recoverable so a path loss racing with close
	// can't arm a stray hold, and snapshot the paths to release under the same
	// lock, so a concurrently added path is either in the snapshot or rejected.
	self.lock.Lock()
	self.recoverable = false
	self.closed = true
	self.cancelHoldLocked()
	paths := *self.paths.Load()
	self.lock.Unlock()

	for _, p := range paths {
		if rp, ok := p.(RouterPath); ok && !rp.IsClosed() {
			xgCloseMsg := channel.NewMessage(edge.ContentTypeXgClose, []byte(self.xg.CircuitId()))
			if err := xgCloseMsg.WithTimeout(5 * time.Second).Send(rp.GetControlSender()); err != nil {
				pfxlog.Logger().WithError(err).Error("failed to send close xg close message")
			}
			break
		}
	}

	// The xgress is fully closed, so no more data will flow in either direction.
	// Mark the owning conn closed so IsClosed reflects it. This is the single
	// point that covers every teardown ending at the xgress: an app-initiated
	// Close, a peer end-of-circuit (e.g. the host's access being revoked), or a
	// router StateClosed that drains then closes. Without this a router-initiated
	// teardown would leave the conn reporting open until the channel went away.
	// close is idempotent, so the app-initiated path (which calls close first) is
	// unaffected. Done before closing the paths so any end-of-circuit it emits can
	// still ride a live path.
	self.conn.close(false)

	// see note in close
	for _, p := range paths {
		if err := p.Close(); err != nil {
			pfxlog.Logger().WithField("circuitId", self.circuitId).WithError(err).Error("failed to close path")
		}
	}
}

// --- xgress.Connection (peer) implementation, pull mode stubs ---

func (self *MultiPathAdapter) Close() error {
	return nil
}

func (self *MultiPathAdapter) LogContext() string {
	return fmt.Sprintf("xg/%s", self.circuitId)
}

func (self *MultiPathAdapter) ReadPayload() ([]byte, map[uint8][]byte, error) {
	return nil, nil, errors.New("should never be called")
}

func (self *MultiPathAdapter) WritePayload([]byte, map[uint8][]byte) (int, error) {
	return 0, errors.New("not available in pull mode")
}

func (self *MultiPathAdapter) FlowFromFabricToXgressClosed() {
	// no-op: in pull mode, ReadAdapter handles cleanup
}

func (self *MultiPathAdapter) HandleControlMsg(controlType xgress.ControlType, headers channel.Headers, responder xgress.ControlReceiver) error {
	//TODO implement me
	panic("implement me")
}
