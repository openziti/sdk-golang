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
	// The run loop transitions to drainDeadlines.
	x.payloadBuffer.Close()

	// Give the run loop time to process the close and enter drainDeadlines
	time.Sleep(10 * time.Millisecond)
	req.True(x.payloadBuffer.IsClosed(), "send buffer should be closed")

	// Setting a future read deadline should still fire via drainDeadlines
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
