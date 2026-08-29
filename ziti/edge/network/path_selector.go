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
	"github.com/openziti/sdk-golang/v2/xgress"
)

// PathSelector chooses which Path carries a given outbound message. Selectors
// are stateless policy: the adapter owns the path set and passes a snapshot
// of it into each selection call.
type PathSelector interface {
	// SelectForPayload chooses the path for a first-send payload. Returns nil
	// if no path can accept it.
	SelectForPayload(paths []Path, payload *xgress.Payload) Path

	// SelectForRetransmit chooses the path for a retransmit. previous is the
	// tag of the path the payload was last sent over. Returns nil if no path
	// can accept it.
	SelectForRetransmit(paths []Path, payload *xgress.Payload, previous xgress.Path) Path

	// Primary returns the default outbound path for messages that have no
	// arrival affinity: standalone/window-update acks and control messages.
	// Returns nil if no path is available.
	Primary(paths []Path) Path
}

// SinglePathSelector always chooses the first path, regardless of liveness.
// With exactly one path attached this matches single-path behavior exactly:
// send errors on a closed transport surface through the send/retransmit error
// paths rather than by re-selection.
type SinglePathSelector struct{}

func (SinglePathSelector) SelectForPayload(paths []Path, _ *xgress.Payload) Path {
	return firstPath(paths)
}

func (SinglePathSelector) SelectForRetransmit(paths []Path, _ *xgress.Payload, _ xgress.Path) Path {
	return firstPath(paths)
}

func (SinglePathSelector) Primary(paths []Path) Path {
	return firstPath(paths)
}

func firstPath(paths []Path) Path {
	if len(paths) == 0 {
		return nil
	}
	return paths[0]
}
