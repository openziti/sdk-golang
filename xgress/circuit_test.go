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
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v4"
	"github.com/openziti/metrics"
	"github.com/stretchr/testify/require"
)

// circuitAdapter is a minimal DataPlaneAdapter that forwards payloads and acks
// to a peer xgress. Unlike testIntermediary, it skips marshal/unmarshal
// round-trips since the wire format is already tested elsewhere.
type circuitAdapter struct {
	peer            *Xgress
	payloadIngester *PayloadIngester
	rtx             *Retransmitter
}

func (self *circuitAdapter) ForwardPayload(payload *Payload, _ *Xgress, _ context.Context) {
	_ = self.peer.SendPayload(payload, 0, PayloadTypeXg)
}

func (self *circuitAdapter) ForwardAcknowledgement(ack *Acknowledgement, _ Address) {
	_ = self.peer.SendAcknowledgement(ack)
}

func (self *circuitAdapter) ForwardControlMessage(*Control, *Xgress) {}
func (self *circuitAdapter) RetransmitPayload(Address, *Payload) error {
	return nil
}

func (self *circuitAdapter) GetRetransmitter() *Retransmitter          { return self.rtx }
func (self *circuitAdapter) GetPayloadIngester() *PayloadIngester      { return self.payloadIngester }
func (self *circuitAdapter) GetMetrics() Metrics                       { return noopMetrics{} }

// e2eConn is a versatile test connection that implements SignalConnection.
// txClosedCh is closed when FlowFromFabricToXgressClosed is called (half-close signal).
type e2eConn struct {
	rxCh        chan rxResult // ReadPayload reads from here; nil means block until close
	txCh        chan txResult // WritePayload sends here; nil means not expected
	txClosedCh  chan struct{} // closed by FlowFromFabricToXgressClosed
	closeNotify chan struct{}
	closed      atomic.Bool
	txClosed    atomic.Bool
}

type rxResult struct {
	data    []byte
	headers map[uint8][]byte
	err     error
}

type txResult struct {
	data    []byte
	headers map[uint8][]byte
}

func (c *e2eConn) LogContext() string { return "e2e-test" }

func (c *e2eConn) ReadPayload() ([]byte, map[uint8][]byte, error) {
	if c.rxCh != nil {
		select {
		case r, ok := <-c.rxCh:
			if !ok {
				return nil, nil, io.EOF
			}
			return r.data, r.headers, r.err
		case <-c.closeNotify:
			return nil, nil, io.EOF
		}
	}
	// No rxCh — block until close
	<-c.closeNotify
	return nil, nil, io.EOF
}

func (c *e2eConn) WritePayload(data []byte, headers map[uint8][]byte) (int, error) {
	if c.txCh == nil {
		panic("WritePayload called on e2eConn with nil txCh")
	}
	select {
	case c.txCh <- txResult{data: data, headers: headers}:
		return len(data), nil
	case <-c.closeNotify:
		return 0, io.EOF
	}
}

func (c *e2eConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeNotify)
	}
	return nil
}

func (c *e2eConn) HandleControlMsg(ControlType, channel.Headers, ControlReceiver) error {
	return nil
}

// FlowFromFabricToXgressClosed implements SignalConnection. Called by txCleanup
// when the tx path exits, signaling half-close.
func (c *e2eConn) FlowFromFabricToXgressClosed() {
	if c.txClosed.CompareAndSwap(false, true) {
		close(c.txClosedCh)
	}
}

type adapterMode int

const (
	modeDefault      adapterMode = iota // rx=rx(), tx=tx()
	modeWriteAdapter                    // rx=WriteAdapter, tx=tx()
	modeReadAdapter                     // rx=rx(), tx=ReadAdapter
	modeBothAdapters                    // rx=WriteAdapter, tx=ReadAdapter
)

func (m adapterMode) String() string {
	switch m {
	case modeDefault:
		return "default"
	case modeWriteAdapter:
		return "writeAdapter"
	case modeReadAdapter:
		return "readAdapter"
	case modeBothAdapters:
		return "bothAdapters"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

func (m adapterMode) usesWriteAdapter() bool {
	return m == modeWriteAdapter || m == modeBothAdapters
}

func (m adapterMode) usesReadAdapter() bool {
	return m == modeReadAdapter || m == modeBothAdapters
}

type testCircuit struct {
	closeNotify     chan struct{}
	payloadIngester *PayloadIngester
	rtx             *Retransmitter

	src     *Xgress
	srcConn *e2eConn
	srcWA   *WriteAdapter
	srcRA   *ReadAdapter

	dst     *Xgress
	dstConn *e2eConn
	dstWA   *WriteAdapter
	dstRA   *ReadAdapter
}

func newTestCircuit(mode adapterMode) *testCircuit {
	tc := &testCircuit{
		closeNotify: make(chan struct{}),
	}

	tc.payloadIngester = NewPayloadIngester(tc.closeNotify)

	metricsRegistry := metrics.NewRegistry("test", nil)
	tc.rtx = NewRetransmitter(mockFaulter{}, metricsRegistry, tc.closeNotify)

	// Configure connections based on mode
	tc.srcConn = &e2eConn{closeNotify: make(chan struct{}), txClosedCh: make(chan struct{})}
	tc.dstConn = &e2eConn{closeNotify: make(chan struct{}), txClosedCh: make(chan struct{})}

	if !mode.usesWriteAdapter() {
		// src needs rxCh for feeding data via rx()
		tc.srcConn.rxCh = make(chan rxResult, 16)
		// dst needs rxCh for feeding data via rx()
		tc.dstConn.rxCh = make(chan rxResult, 16)
	}

	if !mode.usesReadAdapter() {
		// src needs txCh for receiving data via tx()
		tc.srcConn.txCh = make(chan txResult, 16)
		// dst needs txCh for receiving data via tx()
		tc.dstConn.txCh = make(chan txResult, 16)
	}

	opts := DefaultOptions()
	tc.src = NewXgress("test-circuit", "ctrl", "src", tc.srcConn, Initiator, opts, nil)
	tc.dst = NewXgress("test-circuit", "ctrl", "dst", tc.dstConn, Terminator, opts, nil)

	if mode.usesWriteAdapter() {
		tc.srcWA = tc.src.NewWriteAdapter()
		tc.dstWA = tc.dst.NewWriteAdapter()
	}

	if mode.usesReadAdapter() {
		tc.srcRA = tc.src.NewReadAdapter()
		tc.dstRA = tc.dst.NewReadAdapter()
	}

	// Wire data planes: src forwards to dst and vice versa
	tc.src.dataPlane = &circuitAdapter{
		peer:            tc.dst,
		payloadIngester: tc.payloadIngester,
		rtx:             tc.rtx,
	}
	tc.dst.dataPlane = &circuitAdapter{
		peer:            tc.src,
		payloadIngester: tc.payloadIngester,
		rtx:             tc.rtx,
	}

	tc.src.Start()
	tc.dst.Start()

	return tc
}

func (tc *testCircuit) cleanup() {
	tc.src.Close()
	tc.dst.Close()
	select {
	case <-tc.closeNotify:
	default:
		close(tc.closeNotify)
	}
}

// sendPayloads sends sequential uint64 values as payloads from src to dst (or vice versa).
// When using WriteAdapter, it writes to the adapter. When using default rx, it feeds rxCh.
func sendPayloads(t *testing.T, count int, wa *WriteAdapter, rxCh chan<- rxResult) {
	t.Helper()
	for i := 0; i < count; i++ {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(i))
		if wa != nil {
			if _, err := wa.Write(data); err != nil {
				t.Errorf("WriteAdapter.Write failed at %d: %v", i, err)
				return
			}
		} else {
			rxCh <- rxResult{data: data}
		}
	}
}

// recvAndVerifyPayloads receives sequential uint64 values and verifies ordering.
// When using ReadAdapter, it reads from the adapter. When using default tx, it reads from txCh.
func recvAndVerifyPayloads(t *testing.T, req *require.Assertions, count int, ra *ReadAdapter, txCh <-chan txResult) {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for i := 0; i < count; i++ {
		if ra != nil {
			data, _, err := ra.ReadPayload()
			req.NoError(err, "ReadAdapter.ReadPayload failed at %d", i)
			req.Len(data, 8, "payload %d has wrong length", i)
			val := binary.LittleEndian.Uint64(data)
			req.Equal(uint64(i), val, "payload %d out of order", i)
		} else {
			select {
			case result := <-txCh:
				req.Len(result.data, 8, "payload %d has wrong length", i)
				val := binary.LittleEndian.Uint64(result.data)
				req.Equal(uint64(i), val, "payload %d out of order", i)
			case <-timeout:
				req.Failf("timed out", "count at %v", i)
			}
		}
	}
}

func TestCircuitDataFlow(t *testing.T) {
	modes := []adapterMode{modeDefault, modeWriteAdapter, modeReadAdapter, modeBothAdapters}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			req := require.New(t)
			tc := newTestCircuit(mode)
			defer tc.cleanup()

			msgCount := 1000

			// Send payloads src → dst in a goroutine
			go sendPayloads(t, msgCount, tc.srcWA, srcRxCh(tc))

			// Receive and verify on dst side
			recvAndVerifyPayloads(t, req, msgCount, tc.dstRA, dstTxCh(tc))
		})
	}
}

func TestCircuitHalfClose(t *testing.T) {
	modes := []adapterMode{modeDefault, modeWriteAdapter, modeReadAdapter, modeBothAdapters}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			req := require.New(t)
			tc := newTestCircuit(mode)
			defer tc.cleanup()

			msgCount := 100

			// Phase 1: Send data src → dst
			go sendPayloads(t, msgCount, tc.srcWA, srcRxCh(tc))
			recvAndVerifyPayloads(t, req, msgCount, tc.dstRA, dstTxCh(tc))

			// Phase 2: Close src→dst direction
			if tc.srcWA != nil {
				tc.src.CloseRxTimeout()
			} else {
				tc.srcConn.rxCh <- rxResult{err: io.EOF}
			}

			// Verify dst's tx side gets EOF
			if tc.dstRA != nil {
				waitForEOF(t, req, func() error {
					_, _, err := tc.dstRA.ReadPayload()
					return err
				})
			} else {
				// tx() exits and calls txCleanup → FlowFromFabricToXgressClosed
				waitForSignal(t, tc.dstConn.txClosedCh, "dst tx half-close")
			}

			// Phase 3: Send data dst → src (while src→dst is closed)
			go sendPayloads(t, msgCount, tc.dstWA, dstRxCh(tc))
			recvAndVerifyPayloads(t, req, msgCount, tc.srcRA, srcTxCh(tc))

			// Phase 4: Close dst→src direction
			if tc.dstWA != nil {
				tc.dst.CloseRxTimeout()
			} else {
				tc.dstConn.rxCh <- rxResult{err: io.EOF}
			}

			// Verify src's tx side gets EOF
			if tc.srcRA != nil {
				waitForEOF(t, req, func() error {
					_, _, err := tc.srcRA.ReadPayload()
					return err
				})
			} else {
				waitForSignal(t, tc.srcConn.txClosedCh, "src tx half-close")
			}
		})
	}
}

// srcRxCh returns the src connection's rxCh cast to send-only, or nil if not applicable.
func srcRxCh(tc *testCircuit) chan<- rxResult {
	if tc.srcConn.rxCh == nil {
		return nil
	}
	return tc.srcConn.rxCh
}

// dstRxCh returns the dst connection's rxCh cast to send-only, or nil if not applicable.
func dstRxCh(tc *testCircuit) chan<- rxResult {
	if tc.dstConn.rxCh == nil {
		return nil
	}
	return tc.dstConn.rxCh
}

// srcTxCh returns the src connection's txCh cast to receive-only, or nil if not applicable.
func srcTxCh(tc *testCircuit) <-chan txResult {
	if tc.srcConn.txCh == nil {
		return nil
	}
	return tc.srcConn.txCh
}

// dstTxCh returns the dst connection's txCh cast to receive-only, or nil if not applicable.
func dstTxCh(tc *testCircuit) <-chan txResult {
	if tc.dstConn.txCh == nil {
		return nil
	}
	return tc.dstConn.txCh
}

// waitForEOF calls fn repeatedly until it returns io.EOF or times out.
func waitForEOF(t *testing.T, req *require.Assertions, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		req.ErrorIs(err, io.EOF)
	case <-time.After(10 * time.Second):
		req.Fail("timed out waiting for EOF")
	}
}

// waitForSignal waits for the given channel to close or times out.
func waitForSignal(t *testing.T, ch <-chan struct{}, desc string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", desc)
	}
}
