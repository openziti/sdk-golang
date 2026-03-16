package xgress

import (
	"sync/atomic"
	"time"
)

// ReadTimeout is returned by ReadAdapter.ReadPayload when the read deadline expires
// before a payload is available.
type ReadTimeout struct{}

func (ReadTimeout) Error() string   { return "read deadline exceeded" }
func (ReadTimeout) Timeout() bool   { return true }
func (ReadTimeout) Temporary() bool { return true }

// NewReadAdapter creates a ReadAdapter for pull-based payload reading from an Xgress.
func NewReadAdapter(x *Xgress) *ReadAdapter {
	result := &ReadAdapter{
		x: x,
	}
	result.init(&x.payloadBuffer.readDeadlineCb, x.payloadBuffer.events)
	return result
}

// ReadAdapter provides pull-based reading of payloads from the xgress tx path.
// Instead of the tx() goroutine pushing payloads to the peer via WritePayload,
// consumers pull payloads on demand via ReadPayload.
type ReadAdapter struct {
	deadlineControl
	x         *Xgress
	cleanedUp atomic.Bool
}

// SetReadDeadline sets the deadline for ReadPayload calls.
func (self *ReadAdapter) SetReadDeadline(t time.Time) error {
	return self.SetDeadline(t)
}

func (self *ReadAdapter) cleanup() {
	if self.cleanedUp.CompareAndSwap(false, true) {
		self.x.txCleanup()
	}
}

// ReadPayload reads the next complete payload from the xgress receive buffer.
// Returns io.EOF when the circuit ends or the xgress closes.
// Returns *ReadTimeout when the deadline fires before a payload is available.
func (self *ReadAdapter) ReadPayload() ([]byte, map[uint8][]byte, error) {
	data, headers, err := self.x.nextTxPayload(self.Done())
	if err != nil {
		self.cleanup()
		return nil, nil, err
	}
	return data, headers, nil
}
