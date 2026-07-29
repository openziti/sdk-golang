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
	"sync"
	"time"

	"github.com/openziti/foundation/v2/concurrenz"
)

// deadlineControl manages a deadline with notification channel semantics.
// When the deadline expires (or is set in the past), the Done channel is closed.
// Clearing the deadline (zero time) resets the channel to a fresh open one.
//
// Future deadlines use the runtime timer heap. time.AfterFunc only starts a
// goroutine when the deadline fires, so no persistent deadline goroutine is
// needed while the timer is pending.
type deadlineControl struct {
	state *deadlineState
}

func (dc *deadlineControl) init() {
	state := &deadlineState{}
	state.doneNotify.Store(make(chan struct{}))
	dc.state = state
}

// Done returns a channel that is closed when the current deadline expires.
func (dc *deadlineControl) Done() <-chan struct{} {
	return dc.state.doneNotify.Load()
}

// SetDeadline sets the deadline to t. A zero value clears the deadline.
func (dc *deadlineControl) SetDeadline(t time.Time) error {
	return dc.state.setDeadline(t)
}

// currentDeadline returns the deadline in effect, or the zero time if none is set.
func (dc *deadlineControl) currentDeadline() time.Time {
	return dc.state.deadline.Load()
}

// deadlineState holds the mutable half of a deadline. It is a separate allocation so
// that a pending timer callback retains only this, rather than the adapter embedding
// deadlineControl and, through it, the whole Xgress. A pending timer is reachable from
// the runtime timer heap until it fires, so anything its callback captures would
// otherwise stay live for the full duration of the deadline even after the xgress is
// closed and dropped.
type deadlineState struct {
	deadline         concurrenz.AtomicValue[time.Time]
	doneNotify       concurrenz.AtomicValue[chan struct{}]
	doneNotifyClosed bool
	timer            *time.Timer
	lock             sync.Mutex
}

func (st *deadlineState) setDeadline(t time.Time) error {
	st.lock.Lock()
	defer st.lock.Unlock()

	st.deadline.Store(t)

	// Stop any existing timer
	if st.timer != nil {
		st.timer.Stop()
		st.timer = nil
	}

	if t.IsZero() {
		if st.doneNotifyClosed {
			st.doneNotify.Store(make(chan struct{}))
			st.doneNotifyClosed = false
		}
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		// Already expired — close immediately
		if !st.doneNotifyClosed {
			close(st.doneNotify.Load())
			st.doneNotifyClosed = true
		}
		return nil
	}

	// Future deadline — reopen channel if needed
	if st.doneNotifyClosed {
		st.doneNotify.Store(make(chan struct{}))
		st.doneNotifyClosed = false
	}

	st.timer = time.AfterFunc(d, func() { st.fireDeadline(t) })

	return nil
}

// fireDeadline closes the Done channel if the deadline hasn't changed since the
// timer was created.
func (st *deadlineState) fireDeadline(expectedDeadline time.Time) {
	st.lock.Lock()
	defer st.lock.Unlock()
	if st.deadline.Load().Equal(expectedDeadline) && !st.doneNotifyClosed {
		close(st.doneNotify.Load())
		st.doneNotifyClosed = true
	}
}
