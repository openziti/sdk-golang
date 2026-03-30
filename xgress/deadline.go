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
	"sync/atomic"
	"time"

	"github.com/openziti/foundation/v2/concurrenz"
)

// deadlineCallback holds a timer channel and the function to call when it fires.
// It is stored in an atomic slot on the LinkSendBuffer so that the run loop can
// include the timer channel in its select without spawning extra goroutines.
type deadlineCallback struct {
	C    <-chan time.Time
	fire func()
}

// deadlineControl manages a deadline with notification channel semantics.
// When the deadline expires (or is set in the past), the Done channel is closed.
// Clearing the deadline (zero time) resets the channel to a fresh open one.
//
// Future deadlines register a timer channel in the slot for processing by the
// LinkSendBuffer run loop and send a wake event so the loop picks it up.
type deadlineControl struct {
	deadline         concurrenz.AtomicValue[time.Time]
	doneNotify       concurrenz.AtomicValue[chan struct{}]
	doneNotifyClosed bool
	timer            *time.Timer
	slot             *atomic.Pointer[deadlineCallback]
	events           chan sendBufferEvent
	lock             sync.Mutex
}

func (dc *deadlineControl) init(slot *atomic.Pointer[deadlineCallback], events chan sendBufferEvent) {
	dc.doneNotify.Store(make(chan struct{}))
	dc.slot = slot
	dc.events = events
}

// Done returns a channel that is closed when the current deadline expires.
func (dc *deadlineControl) Done() <-chan struct{} {
	return dc.doneNotify.Load()
}

// SetDeadline sets the deadline to t. A zero value clears the deadline.
func (dc *deadlineControl) SetDeadline(t time.Time) error {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	dc.deadline.Store(t)

	// Stop any existing timer
	if dc.timer != nil {
		dc.timer.Stop()
		dc.timer = nil
	}
	dc.slot.Store(nil)

	if t.IsZero() {
		if dc.doneNotifyClosed {
			dc.doneNotify.Store(make(chan struct{}))
			dc.doneNotifyClosed = false
		}
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		// Already expired — close immediately
		if !dc.doneNotifyClosed {
			close(dc.doneNotify.Load())
			dc.doneNotifyClosed = true
		}
		return nil
	}

	// Future deadline — reopen channel if needed
	if dc.doneNotifyClosed {
		dc.doneNotify.Store(make(chan struct{}))
		dc.doneNotifyClosed = false
	}

	dc.timer = time.NewTimer(d)
	dc.slot.Store(&deadlineCallback{
		C:    dc.timer.C,
		fire: func() { dc.fireDeadline(t) },
	})
	// Wake the run loop so it re-evaluates with the new timer channel
	select {
	case dc.events <- deadlineWakeEvent{}:
	default:
	}

	return nil
}

// fireDeadline closes the Done channel if the deadline hasn't changed since the
// timer was created.
func (dc *deadlineControl) fireDeadline(expectedDeadline time.Time) {
	dc.lock.Lock()
	defer dc.lock.Unlock()
	if dc.deadline.Load().Equal(expectedDeadline) && !dc.doneNotifyClosed {
		close(dc.doneNotify.Load())
		dc.doneNotifyClosed = true
	}
}
