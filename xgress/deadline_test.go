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
	"runtime"
	"testing"
	"time"
)

// requireCollected drives the collector and fails if the tracked object is still live.
func requireCollected(t *testing.T, collected <-chan struct{}, msg string) {
	t.Helper()
	for i := 0; i < 20; i++ {
		runtime.GC()
		select {
		case <-collected:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal(msg)
}

// TestPendingDeadlineDoesNotRetainXgress covers the lifetime of a deadline timer. A
// pending timer stays reachable from the runtime timer heap until it fires, so its
// callback must not capture the adapter: doing so would hold the xgress and its buffers
// live for the whole deadline even after the caller has dropped them.
func TestPendingDeadlineDoesNotRetainXgress(t *testing.T) {
	for _, adapter := range []string{"read", "write"} {
		t.Run(adapter, func(t *testing.T) {
			closeNotify := make(chan struct{})
			collected := make(chan struct{})

			// Scoped so the xgress and adapter are unreachable once this returns.
			func() {
				conn := &testConn{
					ch:          make(chan uint64, 1),
					closeNotify: make(chan struct{}),
				}

				x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
				x.dataPlane = noopReceiveHandler{
					payloadIngester: NewPayloadIngester(closeNotify),
				}

				runtime.AddCleanup(x, func(struct{}) { close(collected) }, struct{}{})

				// A deadline far enough out that it cannot fire during the test.
				if adapter == "read" {
					ra := x.NewReadAdapter()
					if err := ra.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
				} else {
					wa := x.NewWriteAdapter()
					if err := wa.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
				}
			}()

			requireCollected(t, collected, "xgress retained by a pending deadline timer")
		})
	}
}

// newDeadlineBenchXgress builds an xgress with a running send buffer and a no-op close
// handler, so tearing it down doesn't log a warning into the benchmark output.
func newDeadlineBenchXgress(b *testing.B) *Xgress {
	closeNotify := make(chan struct{})
	conn := &testConn{
		ch:          make(chan uint64, 1),
		closeNotify: make(chan struct{}),
	}

	x := NewXgress("bench", "ctrl", "bench", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{
		payloadIngester: NewPayloadIngester(closeNotify),
	}
	x.AddCloseHandler(CloseHandlerF(func(*Xgress) {}))

	go x.payloadBuffer.run()
	b.Cleanup(x.Close)

	return x
}

// BenchmarkSetReadDeadline measures the cost of arming a deadline. Deadlines are driven by
// the runtime timer heap rather than by channels the send buffer's run loop selects on, so
// this is the whole per-call cost; the old scheme also charged the run loop a wake event and
// a select re-evaluation that a benchmark on this goroutine would not see.
func BenchmarkSetReadDeadline(b *testing.B) {
	ra := newDeadlineBenchXgress(b).NewReadAdapter()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ra.SetReadDeadline(time.Now().Add(time.Minute))
	}
}

// BenchmarkSetReadDeadlineSetClear measures arm-then-disarm, the shape an application
// timeout loop produces.
func BenchmarkSetReadDeadlineSetClear(b *testing.B) {
	ra := newDeadlineBenchXgress(b).NewReadAdapter()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ra.SetReadDeadline(time.Now().Add(time.Minute))
		_ = ra.SetReadDeadline(time.Time{})
	}
}

func BenchmarkSetWriteDeadline(b *testing.B) {
	wa := newDeadlineBenchXgress(b).NewWriteAdapter()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wa.SetWriteDeadline(time.Now().Add(time.Minute))
	}
}
