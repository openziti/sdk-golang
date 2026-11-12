package network

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

func Test_SeqNormalReadDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newConnReadQ(closeNotify, defaultLegacyRxBufferSize)
	start := time.Now()
	readQ.SetReadDeadline(start.Add(10 * time.Millisecond))

	req := require.New(t)
	_, err := readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})

	first := time.Now()
	req.True(first.Sub(start) >= 10*time.Millisecond)

	_, err = readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})
	req.True(time.Since(first) < time.Millisecond)
}

func Test_SeqNormalReadWithDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newConnReadQ(closeNotify, defaultLegacyRxBufferSize)
	start := time.Now()
	readQ.SetReadDeadline(start.Add(10 * time.Millisecond))

	req := require.New(t)

	data := make([]byte, 877)
	msg := edge.NewDataMsg(1, data)
	req.NoError(readQ.PutSequenced(msg))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(msg, val)
}

func Test_SeqNormalReadWithNoDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newConnReadQ(closeNotify, defaultLegacyRxBufferSize)
	req := require.New(t)

	data := make([]byte, 877)
	msg := edge.NewDataMsg(1, data)
	req.NoError(readQ.PutSequenced(msg))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(msg, val)
}

func Test_SeqReadWithInterrupt(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newConnReadQ(closeNotify, defaultLegacyRxBufferSize)
	start := time.Now()

	req := require.New(t)

	go func() {
		readQ.SetReadDeadline(start.Add(10 * time.Millisecond))
	}()

	_, err := readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})
	first := time.Now()
	req.True(first.Sub(start) >= 10*time.Millisecond)

	_, err = readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})
	req.True(time.Since(first) < time.Millisecond)
}

// newCountSeq returns a sequencer whose values each have size one, so maxSize is a count.
func newCountSeq(closeNotify <-chan struct{}, maxSize int64) *noopSeq[int] {
	return NewNoopSequencer(closeNotify, maxSize, func(int) int64 { return 1 })
}

func Test_SeqPutDoesNotWaitBelowMaxSize(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, 10000)
	req := require.New(t)

	put := make(chan error, 1)
	go func() {
		for i := range 10000 {
			if err := readQ.PutSequenced(i); err != nil {
				put <- err
				return
			}
		}
		put <- nil
	}()

	select {
	case err := <-put:
		req.NoError(err)
	case <-time.After(5 * time.Second):
		req.FailNow("PutSequenced waited for a reader")
	}

	for i := range 10000 {
		val, err := readQ.GetNext()
		req.NoError(err)
		req.Equal(i, val)
	}
}

func Test_SeqPutWakesWaitingReader(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, math.MaxInt64)
	req := require.New(t)

	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = readQ.PutSequenced(7)
	}()

	readQ.SetReadDeadline(time.Now().Add(5 * time.Second))
	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(7, val)
}

// requireBlocked fails unless done stays open for a short while.
func requireBlocked(t *testing.T, done <-chan error, msg string) {
	t.Helper()
	select {
	case err := <-done:
		require.FailNow(t, msg, "returned %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// requirePutReturns waits for done and returns what it delivered.
func requirePutReturns(t *testing.T, done <-chan error, msg string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		require.FailNow(t, msg)
		return nil
	}
}

// A put waits once the queued values reach maxSize and goes in, in order, when the reader takes one.
func Test_SeqPutWaitsAtMaxSize(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, 2)
	req := require.New(t)

	req.NoError(readQ.PutSequenced(1))
	req.NoError(readQ.PutSequenced(2))

	put := make(chan error, 1)
	go func() { put <- readQ.PutSequenced(3) }()
	requireBlocked(t, put, "put didn't wait with maxSize queued")

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(1, val)
	req.NoError(requirePutReturns(t, put, "put didn't resume after the reader took a value"))

	for _, expected := range []int{2, 3} {
		val, err = readQ.GetNext()
		req.NoError(err)
		req.Equal(expected, val)
	}
	req.Zero(readQ.Size())
}

// A value larger than maxSize goes in when the queue is under maxSize, and holds back the next put.
func Test_SeqPutAdmitsOneValuePastMaxSize(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer(closeNotify, 10, func(v int) int64 { return int64(v) })
	req := require.New(t)

	req.NoError(readQ.PutSequenced(4))
	req.NoError(readQ.PutSequenced(100))
	req.Equal(int64(104), readQ.Size())

	put := make(chan error, 1)
	go func() { put <- readQ.PutSequenced(1) }()
	requireBlocked(t, put, "put didn't wait past maxSize")

	for _, expected := range []int{4, 100} {
		val, err := readQ.GetNext()
		req.NoError(err)
		req.Equal(expected, val)
	}
	req.NoError(requirePutReturns(t, put, "put didn't resume after the queue drained"))
}

// Every put waiting for room resumes as the reader makes it.
func Test_SeqPopWakesEveryWaitingPut(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, 1)
	req := require.New(t)
	req.NoError(readQ.PutSequenced(0))

	puts := make(chan error, 2)
	for i := range 2 {
		go func() { puts <- readQ.PutSequenced(i + 1) }()
	}
	requireBlocked(t, puts, "put didn't wait with maxSize queued")

	for range 3 {
		_, err := readQ.GetNext()
		req.NoError(err)
	}
	for range 2 {
		req.NoError(requirePutReturns(t, puts, "waiting put didn't resume"))
	}
}

func Test_SeqPutReturnsOnCloseWhileWaiting(t *testing.T) {
	for _, closeBy := range []string{"closeNotify", "Close"} {
		t.Run(closeBy, func(t *testing.T) {
			closeNotify := make(chan struct{})
			readQ := newCountSeq(closeNotify, 1)
			req := require.New(t)
			req.NoError(readQ.PutSequenced(1))

			put := make(chan error, 1)
			go func() { put <- readQ.PutSequenced(2) }()
			requireBlocked(t, put, "put didn't wait with maxSize queued")

			if closeBy == "Close" {
				readQ.Close()
			} else {
				close(closeNotify)
			}
			req.ErrorIs(requirePutReturns(t, put, "waiting put didn't return on close"), ErrClosed)
		})
	}
}

func Test_SeqReturnsQueuedValuesAfterClose(t *testing.T) {
	for _, closeBy := range []string{"closeNotify", "Close"} {
		t.Run(closeBy, func(t *testing.T) {
			closeNotify := make(chan struct{})
			readQ := newCountSeq(closeNotify, math.MaxInt64)
			req := require.New(t)

			req.NoError(readQ.PutSequenced(1))
			req.NoError(readQ.PutSequenced(2))
			if closeBy == "Close" {
				readQ.Close()
			} else {
				close(closeNotify)
			}

			req.ErrorIs(readQ.PutSequenced(3), ErrClosed)
			for _, expected := range []int{1, 2} {
				val, err := readQ.GetNext()
				req.NoError(err)
				req.Equal(expected, val)
			}
			_, err := readQ.GetNext()
			req.ErrorIs(err, ErrClosed)
		})
	}
}

func Test_SeqDiscardDropsQueuedValues(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, math.MaxInt64)
	req := require.New(t)

	req.NoError(readQ.PutSequenced(1))
	req.NoError(readQ.PutSequenced(2))
	readQ.Discard()

	req.Zero(readQ.Size())
	req.ErrorIs(readQ.PutSequenced(3), ErrClosed)
	_, err := readQ.GetNext()
	req.ErrorIs(err, ErrClosed)

	readQ.lock.Lock()
	defer readQ.lock.Unlock()
	req.Nil(readQ.slots)
}

func Test_SeqReturnsQueuedValuesPastDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, math.MaxInt64)
	req := require.New(t)

	req.NoError(readQ.PutSequenced(1))
	readQ.SetReadDeadline(time.Now().Add(-time.Second))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(1, val)

	_, err = readQ.GetNext()
	req.ErrorIs(err, &ReadTimout{})
}

// PutSequencedBounded queues its value, then waits while more than limit values are queued, counting
// ones put with PutSequenced, and returns once the reader takes one.
func Test_SeqPutBoundedWaitsPastLimit(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, math.MaxInt64)
	req := require.New(t)

	req.NoError(readQ.PutSequencedBounded(1, 3))
	req.NoError(readQ.PutSequencedBounded(2, 3))
	req.NoError(readQ.PutSequenced(3))

	put := make(chan error, 1)
	go func() { put <- readQ.PutSequencedBounded(4, 3) }()
	requireBlocked(t, put, "put didn't wait with the queue past its limit")

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(1, val)
	req.NoError(requirePutReturns(t, put, "put still waiting after the reader made room"))

	for _, expected := range []int{2, 3, 4} {
		val, err := readQ.GetNext()
		req.NoError(err)
		req.Equal(expected, val)
	}
}

// A value put while a PutSequencedBounded waits is read after the waiting one.
func Test_SeqPutBoundedKeepsItsPlaceWhileWaiting(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, math.MaxInt64)
	req := require.New(t)

	req.NoError(readQ.PutSequencedBounded(1, 1))
	put := make(chan error, 1)
	go func() { put <- readQ.PutSequencedBounded(2, 1) }()
	requireBlocked(t, put, "put didn't wait with the queue past its limit")

	req.NoError(readQ.PutSequenced(3))

	for _, expected := range []int{1, 2, 3} {
		val, err := readQ.GetNext()
		req.NoError(err)
		req.Equal(expected, val)
	}
	req.NoError(requirePutReturns(t, put, "put still waiting after the reader made room"))
}

// PutSequencedBounded stops waiting with ErrClosed when the sequencer closes.
func Test_SeqPutBoundedReturnsOnClose(t *testing.T) {
	for _, closeBy := range []string{"closeNotify", "Close"} {
		t.Run(closeBy, func(t *testing.T) {
			closeNotify := make(chan struct{})
			readQ := newCountSeq(closeNotify, math.MaxInt64)
			req := require.New(t)

			req.NoError(readQ.PutSequencedBounded(1, 1))
			put := make(chan error, 1)
			go func() { put <- readQ.PutSequencedBounded(2, 1) }()
			requireBlocked(t, put, "put didn't wait with the queue past its limit")

			if closeBy == "Close" {
				readQ.Close()
			} else {
				close(closeNotify)
			}
			req.ErrorIs(requirePutReturns(t, put, "put still waiting after the sequencer closed"), ErrClosed)
		})
	}
}

// The ring keeps values in order as it wraps, grows and shrinks, and never holds more than four slots
// per queued value beyond its minimum.
func Test_SeqRingKeepsOrderAndBoundsSlots(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := newCountSeq(closeNotify, math.MaxInt64)
	req := require.New(t)
	rng := rand.New(rand.NewPCG(1, 2))

	put, read := 0, 0
	checkRing := func() {
		readQ.lock.Lock()
		slots, count := len(readQ.slots), readQ.count
		readQ.lock.Unlock()
		req.Equal(put-read, count)
		req.True(slots <= seqMinSlots || count >= slots/4, "%d slots for %d values", slots, count)
	}
	readNext := func() {
		val, err := readQ.GetNext()
		req.NoError(err)
		req.Equal(read, val)
		read++
	}

	// phases favor puts, then reads, so the ring grows past a thousand slots, wraps, and shrinks back
	for _, putPercent := range []int{70, 50, 30, 50, 20} {
		for range 20000 {
			if rng.IntN(100) < putPercent {
				req.NoError(readQ.PutSequenced(put))
				put++
			} else if read < put {
				readNext()
			}
			checkRing()
		}
	}
	for read < put {
		readNext()
		checkRing()
	}

	readQ.lock.Lock()
	defer readQ.lock.Unlock()
	req.Equal(seqMinSlots, len(readQ.slots))
}

func Test_GetMaxMsgMux(t *testing.T) {
	maxId := (math.MaxUint32 / 2) - 1
	fmt.Printf("max id: %d\n", maxId)
}
