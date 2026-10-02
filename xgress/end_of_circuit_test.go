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
	"context"
	"testing"
	"time"
)

// stalledDataPlane holds every forwarded payload until its context ends, like a data plane
// whose channel has stopped draining.
type stalledDataPlane struct {
	noopReceiveHandler
}

func (stalledDataPlane) ForwardPayload(_ *Payload, _ *Xgress, ctx context.Context) {
	<-ctx.Done()
}

// TestCloseBoundsEndOfCircuitSend covers closing an xgress whose data plane has stalled. The
// end-of-circuit send gives up at its deadline, so Close returns.
func TestCloseBoundsEndOfCircuitSend(t *testing.T) {
	prevTimeout := endOfCircuitTimeout
	endOfCircuitTimeout = 50 * time.Millisecond
	t.Cleanup(func() { endOfCircuitTimeout = prevTimeout })

	x := newUnstartedTerminator(t)
	x.dataPlane = stalledDataPlane{x.dataPlane.(noopReceiveHandler)}

	done := make(chan struct{})
	go func() {
		x.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return with the data plane stalled")
	}
}
