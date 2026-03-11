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

package network

import (
	"sync"
	"sync/atomic"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
)

// pendingDial tracks a single ConnectV2 attempt's circuit ID assignment. When the router
// sends a route_circuit message, the handler looks up the pendingDial by request ID,
// stores the circuit ID, and registers the edgeConn in the mux's circuit ID map.
type pendingDial struct {
	circuitId  atomic.Value
	done       atomic.Bool
	notifyDone chan struct{}
	sink       edge.MsgSink[any]
	mux        edge.ConnMux[any]
}

// GetCircuitId returns the circuit ID if one has been assigned, or empty string otherwise.
func (pd *pendingDial) GetCircuitId() string {
	if v := pd.circuitId.Load(); v != nil {
		return v.(string)
	}
	return ""
}

func (pd *pendingDial) setCircuitId(circuitId string) {
	pd.circuitId.Store(circuitId)
	if err := pd.mux.AddByCircuitId(circuitId, pd.sink); err != nil {
		pfxlog.Logger().WithField("circuitId", circuitId).WithError(err).Error("failed to register edgeConn in mux by circuit id")
	}
	if pd.done.CompareAndSwap(false, true) {
		close(pd.notifyDone)
	}
}

// DialFailed cleans up the mux registration if a circuit ID was assigned (i.e. route_circuit
// arrived) but the dial subsequently failed.
func (pd *pendingDial) DialFailed() {
	if circuitId := pd.GetCircuitId(); circuitId != "" {
		pd.mux.RemoveByCircuitId(circuitId)
	}
}

// pendingDialTracker manages the set of in-flight ConnectV2 requests, correlating
// route_circuit messages from the router to pending dial attempts by request ID.
type pendingDialTracker struct {
	pending sync.Map // map[string]*pendingDial, keyed by request ID
}

func newPendingDialTracker() *pendingDialTracker {
	return &pendingDialTracker{}
}

// Register creates a new pendingDial for the given request ID. The sink will be registered
// in the mux's circuit ID map when the route_circuit message arrives.
func (t *pendingDialTracker) Register(requestId string, sink edge.MsgSink[any], mux edge.ConnMux[any]) *pendingDial {
	pd := &pendingDial{
		notifyDone: make(chan struct{}),
		sink:       sink,
		mux:        mux,
	}
	t.pending.Store(requestId, pd)
	return pd
}

// Remove cleans up the pending dial entry for the given request ID.
func (t *pendingDialTracker) Remove(requestId string) {
	t.pending.Delete(requestId)
}

// HandleRouteCircuit processes a route_circuit message from the router, extracting the
// request ID and circuit ID, registering the edgeConn in the mux, and notifying the caller.
func (t *pendingDialTracker) HandleRouteCircuit(msg *channel.Message, _ channel.Channel) {
	requestId, _ := msg.GetStringHeader(edge.ConnectRequestIdHeader)
	circuitId, _ := msg.GetStringHeader(edge.CircuitIdHeader)

	if requestId == "" || circuitId == "" {
		pfxlog.Logger().Warn("received route_circuit with missing requestId or circuitId")
		return
	}

	if val, ok := t.pending.Load(requestId); ok {
		pd := val.(*pendingDial)
		pd.setCircuitId(circuitId)
	} else {
		pfxlog.Logger().WithField("requestId", requestId).Warn("received route_circuit for unknown request id")
	}
}
