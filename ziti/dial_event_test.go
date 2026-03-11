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

package ziti

import (
	"testing"

	"github.com/kataras/go-events"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// TestDialListener pins the AddDialListener plumbing: the typed payload reaches
// the handler, and the remover unregisters the listener from the event it was
// registered on.
func TestDialListener(t *testing.T) {
	req := require.New(t)
	ctx := &ContextImpl{EventEmmiter: events.New()}

	var received []DialEvent
	remove := ctx.AddDialListener(func(_ Context, evt DialEvent) {
		received = append(received, evt)
	})

	evt := DialEvent{
		ServiceName: "echo",
		ServiceId:   "svc1",
		RouterName:  "router1",
		Protocol:    edge.DialProtocolConnectV2,
		CircuitId:   "circuit1",
	}
	ctx.Emit(EventDial, evt)
	req.Len(received, 1, "listener fires while registered")
	req.Equal(evt, received[0])
	req.Equal("connect-v2", received[0].Protocol.String())

	remove()
	ctx.Emit(EventDial, evt)
	req.Len(received, 1, "listener must not fire after its remover runs")
}
