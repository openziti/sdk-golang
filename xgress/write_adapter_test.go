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

	"github.com/openziti/metrics"
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
	rtx             *Retransmitter
}

func (c *capturingAdapter) ForwardPayload(payload *Payload, _ *Xgress, _ context.Context) {
	if len(payload.Data) > 0 && !payload.IsCircuitStartFlagSet() && !payload.IsCircuitEndFlagSet() && !payload.IsFlagEOFSet() {
		c.dataCh <- payload.Data
	}
}

func (c *capturingAdapter) RetransmitPayload(Address, *Payload) error { return nil }
func (c *capturingAdapter) ForwardControlMessage(*Control, *Xgress)   {}
func (c *capturingAdapter) ForwardAcknowledgement(*Acknowledgement, Address) {}
func (c *capturingAdapter) GetMetrics() Metrics                       { return noopMetrics{} }
func (c *capturingAdapter) GetPayloadIngester() *PayloadIngester      { return c.payloadIngester }
func (c *capturingAdapter) GetRetransmitter() *Retransmitter          { return c.rtx }

func TestWriteAdapterPushOrdering(t *testing.T) {
	closeNotify := make(chan struct{})
	req := require.New(t)

	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)

	metricsRegistry := metrics.NewRegistry("test", nil)
	adapter := &capturingAdapter{
		dataCh:          make(chan []byte, 1024),
		payloadIngester: NewPayloadIngester(closeNotify),
		rtx:             NewRetransmitter(mockFaulter{}, metricsRegistry, closeNotify),
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

	// Use a past deadline so Done() closes immediately in SetDeadline,
	// without requiring the LinkSendBuffer run loop.
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
