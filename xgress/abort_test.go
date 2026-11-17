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
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The end of one side's connection has to reach the other side as what it was. A graceful end (the
// connection hit EOF) is a half-close: the far connection is told its data is over and can still
// write. An abrupt end (the connection was closed with no end of its data signaled first) is not
// something the far connection can be told is graceful: it is closed, with no end-of-data signal.

// newNegotiatedCircuit starts a circuit and waits until both ends have learned that the other
// supports the native EOF flag. The circuit start exchange delivers that asynchronously, and which
// end marker a side sends depends on it (see sendEOF), so a test that does not wait is racing it.
func newNegotiatedCircuit(t *testing.T) *testCircuit {
	t.Helper()
	tc := newTestCircuit(modeDefault)
	waitForEOFSupport(t, tc.src)
	waitForEOFSupport(t, tc.dst)
	return tc
}

func waitForEOFSupport(t *testing.T, x *Xgress) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !x.PeerSupportsEOF() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the peer's EOF capability")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// outcome of the tx side of the destination connection after the source ended.
type endOfCircuit int

const (
	endedByClose     endOfCircuit = iota // the destination connection was closed
	endedByHalfClose                     // the destination connection was signaled FlowFromFabricToXgressClosed
)

func (e endOfCircuit) String() string {
	if e == endedByClose {
		return "close"
	}
	return "half-close"
}

// waitForEnd reports how the destination connection was told the circuit ended. A half-close may
// be followed by a close once the circuit winds down, so the half-close signal wins: the end is a
// close only if the connection was closed and was never signaled a half-close. The settle pause
// lets a half-close that trails a close land before it is judged.
func waitForEnd(t *testing.T, c *e2eConn) endOfCircuit {
	t.Helper()
	select {
	case <-c.closeNotify:
	case <-c.txClosedCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the destination connection to be told the circuit ended")
	}
	time.Sleep(100 * time.Millisecond)

	if c.txClosed.Load() {
		return endedByHalfClose
	}
	return endedByClose
}

// An abrupt end reaches the peer as a close: the xgress does not invent the end-of-data signal (the
// half-close) for a peer that never sent one.
func TestCircuitAbortReachesPeerAsClose(t *testing.T) {
	req := require.New(t)
	tc := newNegotiatedCircuit(t)
	defer tc.cleanup()

	tc.srcConn.rxCh <- rxResult{err: ErrPeerAborted}

	req.Equal(endedByClose, waitForEnd(t, tc.dstConn), "an abort must not be relayed as a graceful end of data")
	req.False(tc.dstConn.txClosed.Load())
}

// Data written before the abort is still delivered, in order, ahead of the close: the end marker
// travels in sequence behind it, so it is retransmitted like any payload and not lost.
func TestCircuitAbortDeliversDataSentBeforeIt(t *testing.T) {
	req := require.New(t)
	tc := newNegotiatedCircuit(t)
	defer tc.cleanup()

	const count = 50
	sendPayloads(t, count, nil, srcRxCh(tc))
	tc.srcConn.rxCh <- rxResult{err: ErrPeerAborted}

	recvAndVerifyPayloads(t, req, count, nil, dstTxCh(tc))
	req.Equal(endedByClose, waitForEnd(t, tc.dstConn))
}

// A graceful end can be sent as CircuitEnd even by an end that supports EOF: sendEOF falls back to
// it while the end has not yet learned that its peer supports EOF, which a short connection can
// outrun. The receiver must not take that CircuitEnd for an abort, so it stays a half-close.
func TestCircuitGracefulEndSentAsCircuitEndIsAHalfClose(t *testing.T) {
	req := require.New(t)
	tc := newNegotiatedCircuit(t)
	defer tc.cleanup()
	tc.src.flags.Set(CapabilityEOFIndex, false) // src has not heard that dst supports EOF

	tc.srcConn.rxCh <- rxResult{err: io.EOF}

	req.Equal(endedByHalfClose, waitForEnd(t, tc.dstConn))
}

// A circuit torn down underneath its endpoints (the router that carried it went away, the link
// dropped, the controller removed it) ends with no graceful end from the peer, so it is an abort
// too, though no one sent anything to say so.
func TestCircuitUnroutedIsNotAHalfClose(t *testing.T) {
	req := require.New(t)
	tc := newNegotiatedCircuit(t)
	defer tc.cleanup()

	tc.dst.Unrouted()

	req.Equal(endedByClose, waitForEnd(t, tc.dstConn), "a circuit torn down without a graceful end must not look like one")
	req.False(tc.dstConn.txClosed.Load())
}

// Data that reached the xgress before the circuit was unrouted is still delivered, ahead of the close.
func TestCircuitUnroutedDeliversDataQueuedBeforeIt(t *testing.T) {
	req := require.New(t)
	tc := newNegotiatedCircuit(t)
	defer tc.cleanup()

	const count = 20
	sendPayloads(t, count, nil, srcRxCh(tc))
	recvAndVerifyPayloads(t, req, count, nil, dstTxCh(tc))

	tc.dst.Unrouted()

	req.Equal(endedByClose, waitForEnd(t, tc.dstConn))
}

// A peer that closed normally (ErrPeerClosed: the connection is finished for good and had nothing
// abrupt about it, e.g. a datagram conn) is still relayed as a half-close.
func TestCircuitPeerClosedIsStillAHalfClose(t *testing.T) {
	req := require.New(t)
	tc := newNegotiatedCircuit(t)
	defer tc.cleanup()

	tc.srcConn.rxCh <- rxResult{err: ErrPeerClosed}

	req.Equal(endedByHalfClose, waitForEnd(t, tc.dstConn))
}
