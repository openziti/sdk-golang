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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWriteTimeout(t *testing.T) {
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

	writeAdapter := x.NewWriteAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	req.NotNil(writeAdapter.Done())

	// test setting deadline
	start := time.Now()
	err := writeAdapter.SetWriteDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed >= 250*time.Millisecond, "expected at least 250ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test resetting deadline
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed >= 250*time.Millisecond, "expected at least 250ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test setting deadline asynchronously
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(time.Time{})
	req.NoError(err)

	go func() {
		time.Sleep(100 * time.Millisecond)
		req.NoError(writeAdapter.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)))
	}()

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed >= 300*time.Millisecond, "expected at least 300ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test setting deadline and clearing it asynchronously
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	go func() {
		time.Sleep(100 * time.Millisecond)
		req.NoError(writeAdapter.SetWriteDeadline(time.Time{}))
	}()

	select {
	case <-writeAdapter.Done():
		req.Fail("timeout should not have fired")
	case <-time.After(500 * time.Millisecond):
		// expected: deadline was cleared
	}

	// test setting deadline asynchronously and clearing it asynchronously
	err = writeAdapter.SetWriteDeadline(time.Time{})
	req.NoError(err)

	go func() {
		req.NoError(writeAdapter.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)))
		time.Sleep(100 * time.Millisecond)
		req.NoError(writeAdapter.SetWriteDeadline(time.Time{}))
	}()

	select {
	case <-writeAdapter.Done():
		req.Fail("timeout should not have fired")
	case <-time.After(500 * time.Millisecond):
		// expected: deadline was cleared
	}

	// test setting deadline to the past
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(start.Add(-1 * time.Second))
	req.NoError(err)

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}

	// test setting deadline to the past asynchronously
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(time.Now())
	req.NoError(err)

	go func() {
		time.Sleep(5 * time.Millisecond)
		req.NoError(writeAdapter.SetWriteDeadline(time.Now().Add(-250 * time.Millisecond)))
	}()

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 20*time.Millisecond, "expected at most 20ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Fail("timeout didn't fire")
	}
}

// capturingAdapter implements DataPlaneAdapter by sending forwarded payload data to a channel.
type capturingAdapter struct {
	dataCh          chan []byte
	payloadIngester *PayloadIngester
}

func (c *capturingAdapter) ForwardPayload(payload *Payload, _ *Xgress, _ context.Context) Path {
	if len(payload.Data) > 0 && !payload.IsCircuitStartFlagSet() && !payload.IsCircuitEndFlagSet() && !payload.IsFlagEOFSet() {
		c.dataCh <- payload.Data
	}
	return testPath("test")
}

func (c *capturingAdapter) RetransmitPayload(Path, Address, *Payload) (Path, error) {
	return testPath("test"), nil
}
func (c *capturingAdapter) ForwardControlMessage(*Control, *Xgress)                {}
func (c *capturingAdapter) ForwardAcknowledgement(*Acknowledgement, Address, Path) {}
func (c *capturingAdapter) GetMetrics() Metrics                                    { return noopMetrics{} }
func (c *capturingAdapter) GetPayloadIngester() *PayloadIngester                   { return c.payloadIngester }

func TestWriteAdapterPushOrdering(t *testing.T) {
	closeNotify := make(chan struct{})
	req := require.New(t)

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)

	adapter := &capturingAdapter{
		dataCh:          make(chan []byte, 1024),
		payloadIngester: NewPayloadIngester(closeNotify),
	}
	x.dataPlane = adapter

	wa := x.NewWriteAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	msgCount := 1000

	errorCh := make(chan error, 1)
	go func() {
		for i := 0; i < msgCount; i++ {
			data := make([]byte, 8)
			binary.LittleEndian.PutUint64(data, uint64(i))
			if _, err := wa.Write(data); err != nil {
				errorCh <- err
				return
			}
		}
	}()

	timeout := time.After(20 * time.Second)
	for i := 0; i < msgCount; i++ {
		select {
		case err := <-errorCh:
			req.NoError(err)
		case <-timeout:
			req.Failf("timed out", "count at %v", i)
		case data := <-adapter.dataCh:
			val := binary.LittleEndian.Uint64(data)
			req.Equal(uint64(i), val)
		}
	}
}

func TestWriteAdapterDeadlineWrite(t *testing.T) {
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

	wa := x.NewWriteAdapter()

	// A past deadline closes Done() synchronously inside SetDeadline, so no timer is
	// involved. TestWriteAdapterDeadlineWhileWindowBlocked covers the timer path.
	err := wa.SetWriteDeadline(time.Now().Add(-1 * time.Millisecond))
	req.NoError(err)

	_, writeErr := wa.Write([]byte("hello"))
	req.ErrorIs(writeErr, os.ErrDeadlineExceeded)
}

func TestWriteAdapterCloseError(t *testing.T) {
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

	wa := x.NewWriteAdapter()
	go x.payloadBuffer.run()

	// Give the run loop a moment to start
	time.Sleep(10 * time.Millisecond)

	x.payloadBuffer.Close()

	_, writeErr := wa.Write([]byte("hello"))
	req.ErrorIs(writeErr, ErrWriteClosed)
}

// TestWriteAdapterDeadlineAfterHalfClose is the write-side counterpart to
// TestReadAdapterDeadlineAfterHalfClose. Closing the send half stops the send buffer's
// run loop, and a write deadline registered afterward must still fire.
func TestWriteAdapterDeadlineAfterHalfClose(t *testing.T) {
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

	wa := x.NewWriteAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	// Half-close: the send half is done, the xgress as a whole is still alive.
	x.payloadBuffer.Close()
	req.True(x.payloadBuffer.IsClosed(), "send buffer should be closed")
	req.False(x.IsClosed(), "only the send half should be closed")

	// Let the run loop observe the close and exit, so the deadline below cannot be
	// serviced by the loop.
	time.Sleep(10 * time.Millisecond)

	start := time.Now()
	req.NoError(wa.SetWriteDeadline(start.Add(250 * time.Millisecond)))

	select {
	case <-wa.Done():
		passed := time.Since(start)
		req.True(passed >= 250*time.Millisecond, "expected at least 250ms, got %s", passed)
	case <-time.After(2 * time.Second):
		req.Fail("write deadline didn't fire after half-close")
	}
}

// TestWriteAdapterDeadlineWhileWindowBlocked exercises the write-deadline path end to
// end: Write blocks because the send window is full, the deadline expires, and
// BufferPayloadWithDeadline surfaces os.ErrDeadlineExceeded.
func TestWriteAdapterDeadlineWhileWindowBlocked(t *testing.T) {
	closeNotify := make(chan struct{})
	req := require.New(t)

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	// A tiny send window lets a single unacked payload block the buffer.
	// noopReceiveHandler never acks, so once blocked it stays blocked.
	options := DefaultOptions()
	options.TxPortalStartSize = 64
	options.TxPortalMinSize = 64

	x := NewXgress("test", "ctrl", "test", conn, Initiator, options, nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	wa := x.NewWriteAdapter()
	go x.payloadBuffer.run()
	defer x.Close()

	// Generous deadline on the priming write so an unexpected block fails rather than hangs.
	req.NoError(wa.SetWriteDeadline(time.Now().Add(5 * time.Second)))
	_, err := wa.Write(make([]byte, 128))
	req.NoError(err)

	req.Eventually(func() bool {
		return x.payloadBuffer.Inspect().BlockedByLocalWindow
	}, 5*time.Second, 5*time.Millisecond, "send buffer should block once the window is full")

	start := time.Now()
	req.NoError(wa.SetWriteDeadline(start.Add(100 * time.Millisecond)))

	_, err = wa.Write([]byte("blocked"))
	req.ErrorIs(err, os.ErrDeadlineExceeded)
	req.True(time.Since(start) >= 100*time.Millisecond, "write returned before the deadline")
}

// blockWriteAdapterWindow returns an xgress whose send window is full, so the next
// Write parks in BufferPayloadWithDeadline, along with its write adapter and the
// sequence of the single unacked payload holding the window.
func blockWriteAdapterWindow(t *testing.T, req *require.Assertions) (*Xgress, *WriteAdapter, int32) {
	closeNotify := make(chan struct{})

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	options := DefaultOptions()
	options.TxPortalStartSize = 64
	options.TxPortalMinSize = 64

	x := NewXgress("test", "ctrl", "test", conn, Initiator, options, nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}

	wa := x.NewWriteAdapter()
	go x.payloadBuffer.run()
	t.Cleanup(x.Close)

	// The priming payload takes the first sequence and fills the window on its own.
	seq := int32(x.GetSequence())
	req.NoError(wa.SetWriteDeadline(time.Now().Add(5 * time.Second)))
	_, err := wa.Write(make([]byte, 128))
	req.NoError(err)

	req.Eventually(func() bool {
		return x.payloadBuffer.Inspect().BlockedByLocalWindow
	}, 5*time.Second, 5*time.Millisecond, "send buffer should block once the window is full")

	return x, wa, seq
}

// TestWriteAdapterDeadlineClearedWhileBlocked verifies that clearing a deadline while a
// Write is parked cancels the timeout: the write survives the original deadline instant
// and completes once the send window reopens.
func TestWriteAdapterDeadlineClearedWhileBlocked(t *testing.T) {
	req := require.New(t)
	x, wa, seq := blockWriteAdapterWindow(t, req)

	start := time.Now()
	req.NoError(wa.SetWriteDeadline(start.Add(100 * time.Millisecond)))

	writeErr := make(chan error, 1)
	go func() {
		_, err := wa.Write([]byte("blocked"))
		writeErr <- err
	}()

	time.Sleep(30 * time.Millisecond)
	req.NoError(wa.SetWriteDeadline(time.Time{}))

	// Reopen the window only after the original deadline has passed, so a completed
	// write proves the cleared deadline never fired.
	time.Sleep(150 * time.Millisecond)
	ack := NewAcknowledgement("test", Terminator)
	ack.Sequence = []int32{seq}
	req.NoError(x.SendAcknowledgement(ack))

	select {
	case err := <-writeErr:
		req.NoError(err)
		req.True(time.Since(start) >= 100*time.Millisecond, "write completed before the original deadline")
	case <-time.After(5 * time.Second):
		req.Fail("write never completed after the deadline was cleared")
	}
}

// TestWriteAdapterDeadlineExtendedWhileBlocked verifies that extending a deadline while a
// Write is parked moves the timeout out rather than leaving the original in place.
func TestWriteAdapterDeadlineExtendedWhileBlocked(t *testing.T) {
	req := require.New(t)
	_, wa, _ := blockWriteAdapterWindow(t, req)

	start := time.Now()
	req.NoError(wa.SetWriteDeadline(start.Add(100 * time.Millisecond)))

	writeErr := make(chan error, 1)
	go func() {
		_, err := wa.Write([]byte("blocked"))
		writeErr <- err
	}()

	time.Sleep(30 * time.Millisecond)
	req.NoError(wa.SetWriteDeadline(start.Add(400 * time.Millisecond)))

	select {
	case err := <-writeErr:
		req.ErrorIs(err, os.ErrDeadlineExceeded)
		req.True(time.Since(start) >= 400*time.Millisecond,
			"write timed out on the original deadline, not the extended one")
	case <-time.After(5 * time.Second):
		req.Fail("extended deadline never fired")
	}
}

// TestWriteAdapterContext covers the context.Context surface WriteAdapter exposes, which
// forwardPayloadImpl relies on to route writes through BufferPayloadWithDeadline.
func TestWriteAdapterContext(t *testing.T) {
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

	wa := x.NewWriteAdapter()

	deadline, ok := wa.Deadline()
	req.False(ok, "no deadline should be reported before one is set")
	req.True(deadline.IsZero())

	expected := time.Now().Add(time.Minute)
	req.NoError(wa.SetWriteDeadline(expected))
	deadline, ok = wa.Deadline()
	req.True(ok)
	req.True(expected.Equal(deadline), "expected %s, got %s", expected, deadline)

	req.NoError(wa.SetWriteDeadline(time.Time{}))
	deadline, ok = wa.Deadline()
	req.False(ok, "cleared deadline should no longer be reported")
	req.True(deadline.IsZero())

	req.NoError(wa.Err())
	req.Nil(wa.Value("anything"))
}
