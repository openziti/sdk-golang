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
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadAdapterDeadline(t *testing.T) {
	req := require.New(t)

	closeNotify := make(chan struct{})
	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	req.NotNil(ra.Done())

	// test setting deadline
	start := time.Now()
	err := ra.SetReadDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	select {
	case <-ra.Done():
		passed := time.Since(start)
		req.True(passed >= 250*time.Millisecond, "expected at least 250ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-ra.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test resetting deadline
	start = time.Now()
	err = ra.SetReadDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	select {
	case <-ra.Done():
		passed := time.Since(start)
		req.True(passed >= 250*time.Millisecond, "expected at least 250ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test clearing deadline
	err = ra.SetReadDeadline(time.Time{})
	req.NoError(err)

	select {
	case <-ra.Done():
		req.Fail("channel should not be closed after clearing deadline")
	case <-time.After(50 * time.Millisecond):
		// expected
	}

	// test setting deadline to the past
	start = time.Now()
	err = ra.SetReadDeadline(start.Add(-1 * time.Second))
	req.NoError(err)

	select {
	case <-ra.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}
}

func TestReadAdapterPullOrdering(t *testing.T) {
	closeNotify := make(chan struct{})

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()
	defer x.Close()

	msgCount := 100000

	errorCh := make(chan error, 1)

	go func() {
		for i := 0; i < msgCount; i++ {
			data := make([]byte, 8)
			binary.LittleEndian.PutUint64(data, uint64(i))
			payload := &Payload{
				CircuitId: "test",
				Flags:     SetOriginatorFlag(0, Terminator),
				RTT:       0,
				Sequence:  int32(i),
				Headers:   nil,
				Data:      data,
			}
			if err := x.SendPayload(payload, 0, PayloadTypeXg); err != nil {
				errorCh <- err
				x.Close()
				return
			}
		}
	}()

	timeout := time.After(20 * time.Second)

	req := require.New(t)
	for i := 0; i < msgCount; i++ {
		select {
		case err := <-errorCh:
			req.NoError(err)
		case <-timeout:
			req.Failf("timed out", "count at %v", i)
		default:
		}

		data, _, err := ra.ReadPayload()
		req.NoError(err)
		val := binary.LittleEndian.Uint64(data)
		req.Equal(uint64(i), val)
	}
}

func TestReadAdapterDeadlineTimeout(t *testing.T) {
	closeNotify := make(chan struct{})

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	req := require.New(t)

	// set a short deadline and read with no data available
	err := ra.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	req.NoError(err)

	_, _, err = ra.ReadPayload()
	req.Error(err)

	var readTimeout *ReadTimeout
	req.True(errors.As(err, &readTimeout), "expected *ReadTimeout, got %T", err)
	req.True(readTimeout.Timeout())
	req.True(readTimeout.Temporary())
}

func TestReadAdapterDeadlineAfterHalfClose(t *testing.T) {
	closeNotify := make(chan struct{})

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	req := require.New(t)

	// Close the send buffer (half-close: write side done, read side still active).
	// The send-buffer run loop exits while the read half remains active.
	x.payloadBuffer.Close()

	// Give the run loop time to process the close.
	time.Sleep(10 * time.Millisecond)
	req.True(x.payloadBuffer.IsClosed(), "send buffer should be closed")

	// The runtime timer must still fire after the send-buffer loop exits.
	start := time.Now()
	err := ra.SetReadDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	select {
	case <-ra.Done():
		passed := time.Since(start)
		req.True(passed >= 250*time.Millisecond, "expected at least 250ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("read deadline didn't fire after send buffer half-close")
	}

	// A ReadPayload with a deadline should return ReadTimeout, not hang
	err = ra.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	req.NoError(err)

	_, _, err = ra.ReadPayload()
	req.Error(err)

	var readTimeout *ReadTimeout
	req.True(errors.As(err, &readTimeout), "expected *ReadTimeout after half-close, got %T", err)
}

func TestLinkSendBufferRunExitsAfterHalfCloseWithoutReadAdapter(t *testing.T) {
	closeNotify := make(chan struct{})
	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}
	defer x.Close()

	runDone := make(chan struct{})
	go func() {
		x.payloadBuffer.run()
		close(runDone)
	}()

	// A normal router xgress has no ReadAdapter. Closing its send half must
	// stop the run goroutine even while the receive half remains open.
	x.payloadBuffer.Close()

	select {
	case <-runDone:
		require.False(t, x.IsClosed(), "only the send half should be closed")
	case <-time.After(time.Second):
		t.Fatal("link send buffer run goroutine did not exit after half-close")
	}
}

func TestReadAdapterEOFOnClose(t *testing.T) {
	closeNotify := make(chan struct{})

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()
	go x.payloadBuffer.run()

	req := require.New(t)

	// close the xgress in a goroutine, then read should return EOF
	go func() {
		time.Sleep(50 * time.Millisecond)
		x.Close()
	}()

	_, _, err := ra.ReadPayload()
	req.ErrorIs(err, io.EOF)
}

// TestReadAdapterDeadlineDoesNotDisturbStream verifies that a read deadline expiring
// with nothing queued neither consumes nor reorders subsequently delivered payloads.
func TestReadAdapterDeadlineDoesNotDisturbStream(t *testing.T) {
	closeNotify := make(chan struct{})
	req := require.New(t)

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()

	// The send buffer loop must be running: a ReadPayload error runs txCleanup, which
	// buffers a write-failed payload and would otherwise block on newlyBuffered.
	go x.payloadBuffer.run()
	defer x.Close()

	req.NoError(ra.SetReadDeadline(time.Now().Add(50 * time.Millisecond)))

	_, _, err := ra.ReadPayload()
	var readTimeout *ReadTimeout
	req.True(errors.As(err, &readTimeout), "expected *ReadTimeout, got %T", err)

	// Done() stays closed after firing, so the deadline must be cleared before the
	// stream is readable again.
	req.NoError(ra.SetReadDeadline(time.Time{}))

	const payloadCount = 3
	for i := 0; i < payloadCount; i++ {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(i))
		req.NoError(x.SendPayload(&Payload{
			CircuitId: "test",
			Flags:     SetOriginatorFlag(0, Terminator),
			Sequence:  int32(i),
			Data:      data,
		}, 0, PayloadTypeXg))
	}

	for i := 0; i < payloadCount; i++ {
		data, _, err := ra.ReadPayload()
		req.NoError(err)
		req.Equal(uint64(i), binary.LittleEndian.Uint64(data), "payload %v out of order", i)
	}
}

// TestReadAdapterDeadlineDoesNotCloseWriteHalf covers a read deadline expiring on a live
// circuit. A deadline is recoverable, so it must not run the tx-side teardown: that sends
// a write-failed payload, which closes the peer's send buffer permanently and leaves the
// circuit unable to deliver anything further.
func TestReadAdapterDeadlineDoesNotCloseWriteHalf(t *testing.T) {
	req := require.New(t)

	tc := newTestCircuit(modeReadAdapter)
	defer tc.cleanup()

	// let the circuit-start and capabilities exchange settle
	time.Sleep(50 * time.Millisecond)

	req.NoError(tc.srcRA.SetReadDeadline(time.Now().Add(50 * time.Millisecond)))

	_, _, err := tc.srcRA.ReadPayload()
	var readTimeout *ReadTimeout
	req.True(errors.As(err, &readTimeout), "expected *ReadTimeout, got %T", err)

	time.Sleep(50 * time.Millisecond)

	req.False(tc.dst.payloadBuffer.IsClosed(), "read deadline closed the peer's send buffer")

	select {
	case <-tc.srcConn.txClosedCh:
		req.Fail("read deadline signaled fabric-to-xgress close")
	default:
	}

	// The circuit must still carry data in the direction that timed out. Use a generous
	// deadline rather than clearing it, so a wedged circuit fails the read instead of
	// hanging the test.
	req.NoError(tc.srcRA.SetReadDeadline(time.Now().Add(10 * time.Second)))
	go sendPayloads(t, 3, nil, tc.dstConn.rxCh)
	recvAndVerifyPayloads(t, req, 3, tc.srcRA, nil)
}

// TestReadAdapterDeadlineConcurrent covers deadlines set and cleared from another
// goroutine, mirroring the concurrent cases in TestWriteTimeout.
func TestReadAdapterDeadlineConcurrent(t *testing.T) {
	closeNotify := make(chan struct{})
	req := require.New(t)

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	ra := x.NewReadAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	// deadline set asynchronously
	start := time.Now()
	go func() {
		time.Sleep(100 * time.Millisecond)
		req.NoError(ra.SetReadDeadline(time.Now().Add(200 * time.Millisecond)))
	}()

	select {
	case <-ra.Done():
		passed := time.Since(start)
		req.True(passed >= 300*time.Millisecond, "expected at least 300ms, got %s", passed)
	case <-time.After(2 * time.Second):
		req.Fail("timeout didn't fire")
	}

	// pending deadline cleared asynchronously
	req.NoError(ra.SetReadDeadline(time.Time{}))
	req.NoError(ra.SetReadDeadline(time.Now().Add(250 * time.Millisecond)))
	go func() {
		time.Sleep(100 * time.Millisecond)
		req.NoError(ra.SetReadDeadline(time.Time{}))
	}()

	select {
	case <-ra.Done():
		req.Fail("timeout should not have fired after the deadline was cleared")
	case <-time.After(500 * time.Millisecond):
		// expected
	}

	// deadline set and cleared, both asynchronously
	go func() {
		req.NoError(ra.SetReadDeadline(time.Now().Add(250 * time.Millisecond)))
		time.Sleep(100 * time.Millisecond)
		req.NoError(ra.SetReadDeadline(time.Time{}))
	}()

	select {
	case <-ra.Done():
		req.Fail("timeout should not have fired after the deadline was cleared")
	case <-time.After(500 * time.Millisecond):
		// expected
	}

	// deadline moved into the past asynchronously
	start = time.Now()
	req.NoError(ra.SetReadDeadline(time.Now().Add(time.Hour)))
	go func() {
		time.Sleep(5 * time.Millisecond)
		req.NoError(ra.SetReadDeadline(time.Now().Add(-250 * time.Millisecond)))
	}()

	select {
	case <-ra.Done():
	case <-time.After(2 * time.Second):
		req.Fail("timeout didn't fire")
	}
	req.True(time.Since(start) < time.Second, "past deadline should fire promptly")
}
