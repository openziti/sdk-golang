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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLinkSendBufferRunExitsAfterHalfClose covers the send-half close of an xgress with no
// adapters, which is what every router xgress looks like. The run goroutine must exit even
// though the receive half, and so the xgress itself, is still open.
func TestLinkSendBufferRunExitsAfterHalfClose(t *testing.T) {
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
	defer x.Close()

	go x.payloadBuffer.run()

	x.payloadBuffer.Close()

	select {
	case <-x.payloadBuffer.runExited:
		req.False(x.IsClosed(), "only the send half should be closed")
	case <-time.After(time.Second):
		req.Fail("link send buffer run goroutine did not exit after half-close")
	}
}

// TestInspectAfterRunExited covers inspecting a send buffer whose run loop is gone. Nothing
// is left to service the handoff, so Inspect must read the state directly rather than
// waiting out its timeout and reporting an unsynchronized snapshot.
func TestInspectAfterRunExited(t *testing.T) {
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
	defer x.Close()

	go x.payloadBuffer.run()

	detail := x.payloadBuffer.Inspect()
	req.True(detail.AcquiredSafely, "inspect should be serviced by a live run loop")
	req.False(detail.Closed)

	x.payloadBuffer.Close()

	select {
	case <-x.payloadBuffer.runExited:
	case <-time.After(time.Second):
		req.Fail("send buffer run loop did not exit after half-close")
	}

	// Repeated so a request left parked in the handoff channel by an earlier call would
	// show up as a timeout on a later one.
	for i := 0; i < 3; i++ {
		start := time.Now()
		detail = x.payloadBuffer.Inspect()
		elapsed := time.Since(start)

		req.True(detail.AcquiredSafely, "inspect %v should be read directly once run has exited", i)
		req.True(detail.Closed, "inspect %v should report the buffer closed", i)
		req.Less(elapsed, 50*time.Millisecond, "inspect %v waited out the handoff timeout (%s)", i, elapsed)
	}
}
