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
	"context"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/xgress"
)

// PathTypeRouterChannel is the Path.Type for paths carried by an edge router channel.
const PathTypeRouterChannel = "router-channel"

// Path is one transport route a circuit's xgress can send over. It owns all
// transport-specific state for that route (a router channel and mux
// registration, or a direct transport session), including the router-assigned
// xgress address stamped onto outbound messages.
//
// It embeds xgress.Path: the send buffer's view of a path is identity plus the
// per-path metric sinks, and the full transport contract here is a superset of
// that.
type Path interface {
	xgress.Path

	// ForwardPayload sends a data payload over this path.
	ForwardPayload(payload *xgress.Payload, ctx context.Context) error

	// RetransmitPayload re-sends a previously sent payload over this path.
	RetransmitPayload(srcAddr xgress.Address, payload *xgress.Payload) error

	// ForwardControlMessage sends an xgress control message over this path.
	ForwardControlMessage(control *xgress.Control) error

	// SendControlMessageForReply sends an xgress control message over this
	// path and waits for the corresponding control reply. Control messages
	// ride the data plane, so round-trip diagnostics like trace route work
	// over any path type.
	SendControlMessageForReply(control *xgress.Control, timeout time.Duration) (*xgress.Control, error)

	// ForwardAcknowledgement sends an acknowledgement over this path.
	ForwardAcknowledgement(ack *xgress.Acknowledgement, srcAddr xgress.Address) error

	// XgressAddress returns the router-assigned xgress address for this path.
	// Paths with no router-assigned address return the zero value.
	XgressAddress() xgress.Address

	// XgressCtrlId returns the router-assigned controller id for this path.
	// Paths with no router-assigned controller id return the empty string.
	XgressCtrlId() string

	// InspectDetail returns a JSON-marshalable description of this path for
	// inspect output, including transport-specific details.
	InspectDetail() any

	// AddrFragment returns this path's contribution to the conn's remote
	// address rendering: a short, human-readable description of the
	// transport route.
	AddrFragment() string

	// Type returns the transport class of this path, e.g. PathTypeRouterChannel.
	Type() string

	// ID (from xgress.Path) returns the instance id of this path within its
	// transport class. For a router channel path this is the router id; it also
	// keys the path's metric series.

	// IsClosed returns true if this path can no longer carry traffic.
	IsClosed() bool

	// Close releases this path's transport-specific resources, such as its mux
	// registration. It does not close the underlying shared transport.
	Close() error
}

// RouterPath is a Path carried by an edge router channel. It exposes the
// router-channel-specific surfaces needed by control-plane operations:
// inspect reply addressing and circuit teardown.
type RouterPath interface {
	Path

	// WireConnId returns the connId this path is registered under in its
	// router's conn mux.
	WireConnId() uint32

	// GetControlSender returns the sender for the router channel's control underlay.
	GetControlSender() channel.Sender

	// ChannelLabel returns the logical name of the underlying router channel.
	ChannelLabel() string
}
