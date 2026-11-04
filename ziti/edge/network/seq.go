package network

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/openziti/foundation/v2/concurrenz"
	"github.com/pkg/errors"
)

var ErrClosed = errors.New("sequencer closed")

type ReadTimout struct{}

func (r ReadTimout) Error() string {
	return "read timed out"
}

func (r ReadTimout) Timeout() bool {
	return true
}

func (r ReadTimout) Temporary() bool {
	return true
}

// NewNoopSequencer returns a FIFO that hands values to a single reader in the order they were put,
// without limit on how many it holds. Closing closeNotify closes it, as Close does.
func NewNoopSequencer[T any](closeNotify <-chan struct{}) *noopSeq[T] {
	return &noopSeq[T]{
		externalCloseNotify: closeNotify,
		ready:               make(chan struct{}, 1),
		deadlineNotify:      make(chan struct{}),
		closeNotify:         make(chan struct{}),
	}
}

// seqMinSlots is the fewest slots a noopSeq keeps once it has held a value.
const seqMinSlots = 16

type noopSeq[T any] struct {
	lock sync.Mutex
	// slots is a ring holding count values from head, nil until the first put. It doubles when full
	// and halves when less than a quarter full, down to seqMinSlots.
	slots               []T
	head                int
	count               int
	ready               chan struct{}
	externalCloseNotify <-chan struct{}
	deadlineNotify      chan struct{}
	closeNotify         chan struct{}
	closed              atomic.Bool
	deadline            concurrenz.AtomicValue[time.Time]
	readInProgress      atomic.Bool
}

func (self *noopSeq[T]) Close() {
	if self.closed.CompareAndSwap(false, true) {
		close(self.closeNotify)
	}
}

// PutSequenced queues event for GetNext, or returns ErrClosed once the sequencer is closed. It never
// waits on the reader, so it is safe on a channel's receive goroutine; what a reader that falls behind
// leaves queued is bounded only by memory.
func (seq *noopSeq[T]) PutSequenced(event T) error {
	if seq.isClosed() {
		return ErrClosed
	}

	seq.lock.Lock()
	if seq.count == len(seq.slots) {
		seq.resize(max(2*len(seq.slots), seqMinSlots))
	}
	seq.slots[(seq.head+seq.count)%len(seq.slots)] = event
	seq.count++
	seq.lock.Unlock()

	select {
	case seq.ready <- struct{}{}:
	default:
	}
	return nil
}

func (seq *noopSeq[T]) isClosed() bool {
	select {
	case <-seq.externalCloseNotify:
		return true
	case <-seq.closeNotify:
		return true
	default:
		return false
	}
}

// pop removes and returns the oldest queued value, reporting false when none is queued.
func (seq *noopSeq[T]) pop() (T, bool) {
	seq.lock.Lock()
	defer seq.lock.Unlock()

	var val T
	if seq.count == 0 {
		return val, false
	}
	val = seq.slots[seq.head]
	var zero T
	seq.slots[seq.head] = zero
	seq.head = (seq.head + 1) % len(seq.slots)
	seq.count--
	if len(seq.slots) > seqMinSlots && seq.count < len(seq.slots)/4 {
		seq.resize(len(seq.slots) / 2)
	}
	return val, true
}

// resize moves the queued values, oldest first, into a ring of size slots. The caller holds the lock,
// and size is at least count.
func (seq *noopSeq[T]) resize(size int) {
	slots := make([]T, size)
	if end := seq.head + seq.count; end <= len(seq.slots) {
		copy(slots, seq.slots[seq.head:end])
	} else {
		n := copy(slots, seq.slots[seq.head:])
		copy(slots[n:], seq.slots[:end-len(seq.slots)])
	}
	seq.slots = slots
	seq.head = 0
}

// popOr returns the oldest queued value, or err when none is queued.
func (seq *noopSeq[T]) popOr(err error) (T, error) {
	if val, ok := seq.pop(); ok {
		return val, nil
	}
	var zero T
	return zero, err
}

func (seq *noopSeq[T]) SetReadDeadline(deadline time.Time) {
	seq.deadline.Store(deadline)
	if seq.readInProgress.Load() {
		select {
		case seq.deadlineNotify <- struct{}{}:
		case <-time.After(5 * time.Millisecond):
		}
	} else {
		select {
		case seq.deadlineNotify <- struct{}{}:
		default:
		}
	}
}

// GetNext returns the oldest queued value, waiting for one when none is queued. Queued values are
// returned even after the sequencer closes or the read deadline passes; once none remain, it returns
// ErrClosed or a ReadTimout.
func (seq *noopSeq[T]) GetNext() (T, error) {
	seq.readInProgress.Store(true)
	defer seq.readInProgress.Store(false)

	for {
		if val, ok := seq.pop(); ok {
			return val, nil
		}

		deadline := seq.deadline.Load()

		var timeoutCh <-chan time.Time

		if !deadline.IsZero() {
			timeoutCh = time.After(time.Until(deadline))
		}

		select {
		case <-seq.ready:
			continue
		case <-seq.externalCloseNotify:
			return seq.popOr(ErrClosed)
		case <-seq.closeNotify:
			return seq.popOr(ErrClosed)
		case <-seq.deadlineNotify:
			continue
		case <-timeoutCh:
			return seq.popOr(&ReadTimout{})
		}
	}
}
