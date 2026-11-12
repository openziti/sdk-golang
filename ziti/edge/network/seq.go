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

// NewNoopSequencer returns a FIFO that hands values to a single reader in the order they were put.
// sizeOf gives each value's size; once the queued values total maxSize, PutSequenced waits for the
// reader, while PutSequencedBounded waits on a count instead. Closing closeNotify closes it, as Close
// does.
func NewNoopSequencer[T any](closeNotify <-chan struct{}, maxSize int64, sizeOf func(T) int64) *noopSeq[T] {
	return &noopSeq[T]{
		maxSize:             maxSize,
		sizeOf:              sizeOf,
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
	slots []T
	head  int
	count int
	// size is the total sizeOf of the queued values.
	size    int64
	maxSize int64
	sizeOf  func(T) int64
	// space is non-nil while a put waits for the reader, and the next pop closes it. Every waiting put
	// shares it, so one pop wakes them all.
	space               chan struct{}
	closed              bool
	ready               chan struct{}
	externalCloseNotify <-chan struct{}
	deadlineNotify      chan struct{}
	closeNotify         chan struct{}
	deadline            concurrenz.AtomicValue[time.Time]
	readInProgress      atomic.Bool
}

// Close closes the sequencer: puts return ErrClosed, and GetNext returns what is still queued, then
// ErrClosed. It is safe to call more than once.
func (seq *noopSeq[T]) Close() {
	seq.lock.Lock()
	defer seq.lock.Unlock()
	seq.closeLocked()
}

// Discard closes the sequencer, as Close does, and drops whatever is queued.
func (seq *noopSeq[T]) Discard() {
	seq.lock.Lock()
	defer seq.lock.Unlock()
	seq.closeLocked()
	seq.slots, seq.head, seq.count, seq.size = nil, 0, 0, 0
}

func (seq *noopSeq[T]) closeLocked() {
	if !seq.closed {
		seq.closed = true
		close(seq.closeNotify)
	}
}

// PutSequenced queues event for GetNext. While the queued values total maxSize or more it first waits
// for the reader to take some, so the queue holds at most maxSize plus one value. It returns ErrClosed
// once the sequencer is closed, including while it waits.
func (seq *noopSeq[T]) PutSequenced(event T) error {
	for {
		seq.lock.Lock()
		if seq.isClosed() {
			seq.lock.Unlock()
			return ErrClosed
		}
		if seq.size < seq.maxSize {
			seq.push(event)
			seq.lock.Unlock()
			seq.signalReady()
			return nil
		}
		space := seq.spaceSignal()
		seq.lock.Unlock()

		select {
		case <-space:
		case <-seq.externalCloseNotify:
			return ErrClosed
		case <-seq.closeNotify:
			return ErrClosed
		}
	}
}

// PutSequencedBounded queues event for GetNext, then waits while more than limit values are queued.
// It ignores maxSize. Because event is queued before the wait, anything put after it, by any
// goroutine, is read after it. It returns ErrClosed if the sequencer is closed before event is queued
// or while it waits.
func (seq *noopSeq[T]) PutSequencedBounded(event T, limit int) error {
	seq.lock.Lock()
	if seq.isClosed() {
		seq.lock.Unlock()
		return ErrClosed
	}
	seq.push(event)
	seq.lock.Unlock()
	seq.signalReady()

	for {
		seq.lock.Lock()
		if seq.count <= limit {
			seq.lock.Unlock()
			return nil
		}
		space := seq.spaceSignal()
		seq.lock.Unlock()

		select {
		case <-space:
		case <-seq.externalCloseNotify:
			return ErrClosed
		case <-seq.closeNotify:
			return ErrClosed
		}
	}
}

// Size reports the total sizeOf of the queued values.
func (seq *noopSeq[T]) Size() int64 {
	seq.lock.Lock()
	defer seq.lock.Unlock()
	return seq.size
}

// MaxSize reports the size at which PutSequenced waits for the reader.
func (seq *noopSeq[T]) MaxSize() int64 {
	return seq.maxSize
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

// push appends event to the ring, growing it when full. The caller holds the lock.
func (seq *noopSeq[T]) push(event T) {
	if seq.count == len(seq.slots) {
		seq.resize(max(2*len(seq.slots), seqMinSlots))
	}
	seq.slots[(seq.head+seq.count)%len(seq.slots)] = event
	seq.count++
	seq.size += seq.sizeOf(event)
}

// spaceSignal returns a channel the next pop closes. The caller holds the lock.
func (seq *noopSeq[T]) spaceSignal() <-chan struct{} {
	if seq.space == nil {
		seq.space = make(chan struct{})
	}
	return seq.space
}

func (seq *noopSeq[T]) signalReady() {
	select {
	case seq.ready <- struct{}{}:
	default:
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
	seq.size -= seq.sizeOf(val)
	if len(seq.slots) > seqMinSlots && seq.count < len(seq.slots)/4 {
		seq.resize(len(seq.slots) / 2)
	}
	if seq.space != nil {
		close(seq.space)
		seq.space = nil
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
