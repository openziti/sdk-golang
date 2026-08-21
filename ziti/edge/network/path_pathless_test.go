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

	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/stretchr/testify/require"
)

// newPathlessTestConn builds a fully-wired edgeConnXgress (write/read adapters,
// chunk reader, started xgress) over a single RouterChannelPath, for exercising
// the pathless policy.
func newPathlessTestConn(closeNotify chan struct{}) (*edgeConnXgress, *MultiPathAdapter, *RouterChannelPath, *countingSender) {
	path, sender := newTestPath("a", 1)
	env := testEnv{ingester: xgress.NewPayloadIngester(closeNotify), metrics: noopTestMetrics{}}
	adapter := NewMultiPathAdapter("c1", env, SinglePathSelector{}, path)

	conn := &edgeConnXgress{
		edgeConnBase: edgeConnBase{circuitId: "c1", closeNotify: make(chan struct{})},
		adapter:      adapter,
		localId:      nextLocalConnId(),
	}
	adapter.conn = conn
	path.conn = conn

	xg := xgress.NewXgress("c1", "ctrl", "addr", adapter, xgress.Initiator, xgress.DefaultOptions(), nil)
	adapter.xg = xg
	xg.AddCloseHandler(adapter)
	xg.SetDataPlaneAdapter(adapter)

	conn.xg = xg
	conn.writeAdapter = xg.NewWriteAdapter()
	conn.readAdapter = xg.NewReadAdapter()
	conn.initChunkReader()

	xg.Start() // sends CircuitStart over the initial path, starts the send-buffer loop
	return conn, adapter, path, sender
}

// TestPathlessClosesWhenNotRecoverable: an ordinary single-path conn whose
// path is lost tears the xgress down, exactly as before multi-path.
func TestPathlessClosesWhenNotRecoverable(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, _, path, _ := newPathlessTestConn(closeNotify)
	req.False(conn.xg.IsClosed())

	// path's channel dies
	req.NoError(path.HandleMuxClose())

	req.True(conn.xg.IsClosed())
	req.True(conn.IsClosed())
}

// TestPathlessHoldsWhenRecoverable: a recoverable conn survives loss of its
// last path; the xgress stays open and adding a path resumes flow.
func TestPathlessHoldsWhenRecoverable(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, adapter, path, _ := newPathlessTestConn(closeNotify)
	conn.SetRecoverable(time.Minute)

	req.NoError(path.HandleMuxClose())

	// xgress and conn survive the gap
	req.False(conn.xg.IsClosed())
	req.False(conn.IsClosed())
	req.Empty(adapter.Paths())

	// a new path resumes flow
	pathB, senderB := newTestPath("b", 2)
	pathB.conn = conn
	adapter.AddPath(pathB)

	req.NoError(conn.SetWriteDeadline(time.Now().Add(time.Second)))
	_, err := conn.Write([]byte("after-recovery"))
	req.NoError(err)
	req.Eventually(func() bool { return senderB.payloads.Load() >= 1 }, time.Second, 5*time.Millisecond)
	req.False(conn.xg.IsClosed())
}

// TestPathlessHoldExpires: a recoverable conn whose hold window expires with no
// replacement path closes the xgress.
func TestPathlessHoldExpires(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, _, path, _ := newPathlessTestConn(closeNotify)
	conn.SetRecoverable(50 * time.Millisecond)

	req.NoError(path.HandleMuxClose())
	req.False(conn.xg.IsClosed())

	req.Eventually(func() bool { return conn.xg.IsClosed() }, time.Second, 5*time.Millisecond)
	req.True(conn.IsClosed())
}

// TestPathlessAppCloseBypassesHold: app-initiated close tears down immediately
// even on a recoverable conn; the hold only ever applies to transport loss.
func TestPathlessAppCloseBypassesHold(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, adapter, _, _ := newPathlessTestConn(closeNotify)
	conn.SetRecoverable(time.Minute)

	req.NoError(conn.Close())
	req.True(conn.IsClosed())

	// recoverable was cleared by close; a subsequent path loss does not hold
	req.Equal(closeXgress, adapter.RemovePath(adapter.Paths()[0]))
}

// TestPathlessAbandonRecoveryCloses: clearing the recoverable mark while the
// conn is pathless (recovery abandoned during a hold) tears the xgress down,
// rather than leaking it open forever with no transport and a cancelled hold.
func TestPathlessAbandonRecoveryCloses(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, adapter, path, _ := newPathlessTestConn(closeNotify)
	conn.SetRecoverable(time.Minute)

	req.NoError(path.HandleMuxClose())
	req.Empty(adapter.Paths())
	req.False(conn.xg.IsClosed()) // held open by the (long) recoverable timer

	conn.ClearRecoverable() // recovery abandoned while still pathless

	req.True(conn.xg.IsClosed())
	req.True(conn.IsClosed())
}

// TestPathlessClearRecoverableWithPathDoesNotClose: clearing the recoverable
// mark while a path is still attached (recovery succeeded, or an ordinary live
// conn) only drops the flag; it does not close the xgress.
func TestPathlessClearRecoverableWithPathDoesNotClose(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, _, _, _ := newPathlessTestConn(closeNotify)
	conn.SetRecoverable(time.Minute)

	conn.ClearRecoverable()

	req.False(conn.xg.IsClosed())
	req.False(conn.IsClosed())
}

// TestPathlessWritesBufferedAndFlushed: writes during a pathless hold stay
// buffered and unsent (never marked sent), and are flushed over a path added
// later. This is the resume-after-gap behavior recovery relies on.
func TestPathlessWritesBufferedAndFlushed(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, adapter, path, _ := newPathlessTestConn(closeNotify)
	conn.SetRecoverable(time.Minute)

	req.NoError(path.HandleMuxClose())
	req.Empty(adapter.Paths())

	// write while pathless: buffered, no transport to take it
	req.NoError(conn.SetWriteDeadline(time.Now().Add(time.Second)))
	_, err := conn.Write([]byte("during-gap"))
	req.NoError(err)

	// add a path: the buffered window is flushed over it
	pathB, senderB := newTestPath("b", 2)
	pathB.conn = conn
	adapter.AddPath(pathB)

	req.Eventually(func() bool { return senderB.payloads.Load() >= 1 }, time.Second, 5*time.Millisecond)
	req.False(conn.xg.IsClosed())
}

// TestPathlessLateAddedPathDiscarded: a path offered after xgress teardown has
// taken its snapshot of paths to release is rejected and closed, rather than
// left registered in its mux feeding a closed xgress.
func TestPathlessLateAddedPathDiscarded(t *testing.T) {
	req := require.New(t)
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	conn, adapter, path, _ := newPathlessTestConn(closeNotify)

	// not recoverable, so losing the last path tears the xgress down and runs the
	// adapter's close handler synchronously
	req.NoError(path.HandleMuxClose())
	req.True(conn.xg.IsClosed())

	pathB, _ := newTestPath("b", 2)
	pathB.conn = conn

	req.False(adapter.AddPath(pathB), "late-added path was accepted after teardown")
	req.NotContains(adapter.Paths(), pathB)
	req.True(pathB.IsClosed(), "late-added path was left open, leaking its mux registration")
}

// TestPathlessTerminalDecisionClaimsClosed: a terminal decision claims the adapter
// in the same lock acquisition that makes it, so a path offered before the close it
// triggers is rejected rather than accepted into an adapter that is going away.
// Accepting one makes AddPath report success to a takeover that has already
// re-spliced the circuit on the controller, for a conn about to be torn down.
//
// Only the RemovePath site is observable from a test: it returns its decision to a
// caller that performs the close, so there is a real gap to look at. The hold-expiry
// and abandon-recovery sites perform the close themselves, and teardown also sets
// closed, so from outside the two orderings are indistinguishable. What is testable
// there is the opposite error, claiming the adapter when the decision was not
// terminal, which would strand recovery permanently.
func TestPathlessTerminalDecisionClaimsClosed(t *testing.T) {
	req := require.New(t)

	t.Run("last path lost while not recoverable rejects", func(t *testing.T) {
		closeNotify := make(chan struct{})
		defer close(closeNotify)
		conn, adapter, path, _ := newPathlessTestConn(closeNotify)

		// the decision, without yet running the caller's teardown
		req.Equal(closeXgress, adapter.RemovePath(path))

		pathB, _ := newTestPath("b", 2)
		pathB.conn = conn
		req.False(adapter.AddPath(pathB), "path accepted after the xgress was condemned")
		req.True(pathB.IsClosed())
	})

	t.Run("held for recovery still accepts", func(t *testing.T) {
		closeNotify := make(chan struct{})
		defer close(closeNotify)
		conn, adapter, path, _ := newPathlessTestConn(closeNotify)
		conn.SetRecoverable(time.Minute)

		// holding open is not terminal: this is precisely when a path must attach
		req.Equal(holdingForRecovery, adapter.RemovePath(path))

		pathB, _ := newTestPath("b", 2)
		pathB.conn = conn
		req.True(adapter.AddPath(pathB), "recovery path rejected while holding open")
		req.False(pathB.IsClosed())
	})

	t.Run("recovery abandoned with a path attached still accepts", func(t *testing.T) {
		closeNotify := make(chan struct{})
		defer close(closeNotify)
		conn, adapter, _, _ := newPathlessTestConn(closeNotify)
		conn.SetRecoverable(time.Minute)

		// a path is still attached, so dropping the mark is not terminal
		conn.ClearRecoverable()
		req.False(conn.xg.IsClosed())

		pathB, _ := newTestPath("b", 2)
		pathB.conn = conn
		req.True(adapter.AddPath(pathB), "path rejected by a live adapter")
		req.False(pathB.IsClosed())
	})
}
