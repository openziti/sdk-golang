package network

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

func Test_SeqNormalReadDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[*channel.Message](closeNotify)
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

	readQ := NewNoopSequencer[*channel.Message](closeNotify)
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

	readQ := NewNoopSequencer[*channel.Message](closeNotify)
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

	readQ := NewNoopSequencer[*channel.Message](closeNotify)
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

func Test_SeqPutDoesNotWaitForReader(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[int](closeNotify)
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

	readQ := NewNoopSequencer[int](closeNotify)
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

func Test_SeqReturnsQueuedValuesAfterClose(t *testing.T) {
	for _, closeBy := range []string{"closeNotify", "Close"} {
		t.Run(closeBy, func(t *testing.T) {
			closeNotify := make(chan struct{})
			readQ := NewNoopSequencer[int](closeNotify)
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

func Test_SeqReturnsQueuedValuesPastDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[int](closeNotify)
	req := require.New(t)

	req.NoError(readQ.PutSequenced(1))
	readQ.SetReadDeadline(time.Now().Add(-time.Second))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(1, val)

	_, err = readQ.GetNext()
	req.ErrorIs(err, &ReadTimout{})
}

// The ring keeps values in order as it wraps, grows and shrinks, and never holds more than four slots
// per queued value beyond its minimum.
func Test_SeqRingKeepsOrderAndBoundsSlots(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[int](closeNotify)
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
