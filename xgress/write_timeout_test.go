package xgress

import (
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestWriteTimeout(t *testing.T) {
	req := require.New(t)

	writeAdapter := NewWriteAdapter(nil)
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
		req.Error(errors.New("timeout didn't fire"))
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
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
		req.Error(errors.New("timeout didn't fire"))
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
	}

	// test setting deadline asynchronously
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(time.Time{})
	req.NoError(err)

	go func() {
		time.Sleep(100 * time.Millisecond)
		err = writeAdapter.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		req.NoError(err)
	}()

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed >= 300*time.Millisecond, "expected at least 300ms, got %s", passed)
		req.True(passed <= 350*time.Millisecond, "expected at most 350ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
	}

	// test that deadline doesn't get reset on its own after timeout
	start = time.Now()
	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 10*time.Millisecond, "expected at most 10ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
	}

	// test setting deadline and clearing it asynchronously
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(start.Add(250 * time.Millisecond))
	req.NoError(err)

	go func() {
		time.Sleep(100 * time.Millisecond)
		err = writeAdapter.SetWriteDeadline(time.Time{})
		req.NoError(err)
	}()

	select {
	case <-writeAdapter.Done():
		req.Error(errors.New("timeout should not have fired"))
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
	}

	// test setting deadline asynchronously and clearing it asynchronously
	err = writeAdapter.SetWriteDeadline(time.Time{})
	req.NoError(err)

	go func() {
		err = writeAdapter.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		req.NoError(err)
		time.Sleep(100 * time.Millisecond)
		err = writeAdapter.SetWriteDeadline(time.Time{})
		req.NoError(err)

	}()

	select {
	case <-writeAdapter.Done():
		req.Error(errors.New("timeout should not have fired"))
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
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
		req.Error(errors.New("timeout didn't fire"))
	}

	// test setting deadline to the past asynchronously
	start = time.Now()
	err = writeAdapter.SetWriteDeadline(time.Now())
	req.NoError(err)

	go func() {
		time.Sleep(5 * time.Millisecond)
		err = writeAdapter.SetWriteDeadline(time.Now().Add(-250 * time.Millisecond))
		req.NoError(err)
	}()

	select {
	case <-writeAdapter.Done():
		passed := time.Since(start)
		req.True(passed < 20*time.Millisecond, "expected at most 20ms, got %s", passed)
	case <-time.After(500 * time.Millisecond):
		req.Error(errors.New("timeout didn't fire"))
	}
}
