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
	"fmt"
	"sync/atomic"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/inspect"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/pkg/errors"
)

var _ Path = (*RouterChannelPath)(nil)
var _ RouterPath = (*RouterChannelPath)(nil)
var _ xgress.Path = (*RouterChannelPath)(nil)
var _ edge.MsgSink[any] = (*RouterChannelPath)(nil)

// RouterChannelPath is a Path that sends over an edge router channel. It owns
// the router-specific state for one transport route: the channel senders, the
// router-assigned xgress address and the conn's registration in that router's
// conn mux. It is also the mux sink for inbound messages arriving via its
// router, registered under its wire connId; inbound dispatch is delegated to
// the owning conn.
type RouterChannelPath struct {
	conn          *edgeConnXgress
	sender        RouterSender
	connId        uint32
	mux           edge.ConnMux[any]
	ctrlSender    channel.Sender
	defaultSender channel.Sender
	routerId      string
	channelLabel  string
	xgressAddress xgress.Address
	xgressCtrlId  string
	closed        atomic.Bool

	// per-path metrics. Written only from the send-buffer run goroutine
	// (RecordRtt/RecordLoss), read from inspect; atomics give safe publication.
	rttMillis atomic.Uint32 // smoothed EWMA round-trip time; 0 until first sample
	lossCount atomic.Uint64 // payloads retransmitted away from this path
}

// newRouterChannelPath builds a path over the given router channel for a conn,
// binding the router-assigned wire connId, xgress address and controller id. It
// does not register the path in the mux; the caller does that (replacing a
// pending placeholder on a dial, or on a reroute takeover) before the path is
// used. Shared by the initial dial and by reroute takeover so both build the
// path identically.
func newRouterChannelPath(conn *edgeConnXgress, ch edge.SdkChannel, mux edge.ConnMux[any], connId uint32, ctrlId string, addr xgress.Address) *RouterChannelPath {
	msgCh := edge.NewEdgeMsgChannel(ch, connId)
	return &RouterChannelPath{
		conn:          conn,
		sender:        newRouterSender(*msgCh),
		connId:        connId,
		mux:           mux,
		ctrlSender:    ch.GetControlSender(),
		defaultSender: msgCh.GetDefaultSender(),
		routerId:      ch.GetChannel().Id(),
		channelLabel:  ch.GetChannel().LogicalName(),
		xgressAddress: addr,
		xgressCtrlId:  ctrlId,
	}
}

// register adds this path to its router's conn mux under its wire connId. It
// must be called before the conn's xgress starts, so inbound messages have a
// sink the moment terminator-side data is released.
func (self *RouterChannelPath) register() error {
	return self.mux.Add(self)
}

// --- Path implementation ---

// ForwardPayload sends the payload over this path's router channel. No
// ConnIdHeader is stamped: the router routes xgress payloads by the circuit
// id already in the message, same as retransmits and acks.
func (self *RouterChannelPath) ForwardPayload(payload *xgress.Payload, ctx context.Context) error {
	msg := payload.Marshall()
	return self.sender.SendPayload(msg, ctx)
}

// RetransmitPayload re-sends a previously sent payload over this path. It blocks
// until the payload reaches the wire or the channel closes, with no deadline. That
// is deliberate backpressure rather than an oversight: the caller is a goroutine
// dedicated to draining the retransmit list onto this one channel, so waiting is
// what applies backpressure and nothing is queued behind it to starve. A caller
// that can offer a live alternative path needs a bounded or non-blocking send
// instead, so it can place the payload elsewhere rather than wait here.
func (self *RouterChannelPath) RetransmitPayload(srcAddr xgress.Address, payload *xgress.Payload) error {
	msg := payload.Marshall()
	return self.sender.SendPayload(msg, context.Background())
}

func (self *RouterChannelPath) ForwardControlMessage(control *xgress.Control) error {
	msg := control.Marshall()
	return self.sender.SendControlMessage(msg)
}

// SendControlMessageForReply sends the control message over this path's
// router channel and waits for the reply, which the channel layer correlates
// by sequence. The wire connId is stamped so the router can attribute the
// request to this conn.
func (self *RouterChannelPath) SendControlMessageForReply(control *xgress.Control, timeout time.Duration) (*xgress.Control, error) {
	msg := control.Marshall()
	msg.PutUint32Header(edge.ConnIdHeader, self.connId)

	resp, err := msg.WithTimeout(timeout).SendForReply(self.defaultSender)
	if err != nil {
		return nil, err
	}
	if resp.ContentType != edge.ContentTypeXgControl {
		return nil, errors.Errorf("unexpected response content type: %v", resp.ContentType)
	}
	return xgress.UnmarshallControl(resp)
}

// ForwardAcknowledgement sends the ack over this path's router channel. The
// srcAddr is not put on the wire: the router derives the forwarder source
// address from the channel the ack arrives on.
func (self *RouterChannelPath) ForwardAcknowledgement(ack *xgress.Acknowledgement, srcAddr xgress.Address) error {
	msg := ack.Marshall()
	return self.sender.SendAcknowledgement(msg)
}

// --- xgress.Path metrics methods (per-path metrics) ---

// RecordRtt folds a raw round-trip sample into this path's EWMA. The halving
// average bounds how far any one sample (including a late duplicate-ack sample)
// can move the estimate. Called only from the send-buffer run goroutine.
func (self *RouterChannelPath) RecordRtt(sampleMillis uint16) {
	last := uint16(self.rttMillis.Load())
	if last > 0 {
		sampleMillis = (sampleMillis + last) >> 1
	}
	self.rttMillis.Store(uint32(sampleMillis))
}

// RecordLoss increments this path's loss count. Called only from the
// send-buffer run goroutine.
func (self *RouterChannelPath) RecordLoss() {
	self.lossCount.Add(1)
}

// Rtt returns this path's current smoothed round-trip estimate in
// milliseconds, or 0 if no sample has been recorded.
func (self *RouterChannelPath) Rtt() uint16 {
	return uint16(self.rttMillis.Load())
}

// LossCount returns the number of payloads retransmitted away from this path.
func (self *RouterChannelPath) LossCount() uint64 {
	return self.lossCount.Load()
}

// RouterChannelPathDetail describes a RouterChannelPath in inspect output.
type RouterChannelPathDetail struct {
	Type         string `json:"type"`
	RouterId     string `json:"routerId"`
	WireConnId   uint32 `json:"wireConnId"`
	ChannelLabel string `json:"channelLabel"`
	Address      string `json:"address"`
	CtrlId       string `json:"ctrlId"`
	Closed       bool   `json:"closed"`
	RttMillis    uint16 `json:"rttMillis"`
	LossCount    uint64 `json:"lossCount"`
}

func (self *RouterChannelPath) InspectDetail() any {
	return &RouterChannelPathDetail{
		Type:         PathTypeRouterChannel,
		RouterId:     self.routerId,
		WireConnId:   self.connId,
		ChannelLabel: self.channelLabel,
		Address:      string(self.xgressAddress),
		CtrlId:       self.xgressCtrlId,
		Closed:       self.IsClosed(),
		RttMillis:    self.Rtt(),
		LossCount:    self.LossCount(),
	}
}

// AddrFragment renders this path's route in the format RemoteAddr has
// historically reported for router-channel backed conns.
func (self *RouterChannelPath) AddrFragment() string {
	return fmt.Sprintf("ziti-edge-router connId=%v, logical=%v", self.connId, self.channelLabel)
}

func (self *RouterChannelPath) XgressAddress() xgress.Address {
	return self.xgressAddress
}

func (self *RouterChannelPath) XgressCtrlId() string {
	return self.xgressCtrlId
}

func (self *RouterChannelPath) Type() string {
	return PathTypeRouterChannel
}

func (self *RouterChannelPath) ID() string {
	return self.routerId
}

func (self *RouterChannelPath) IsClosed() bool {
	return self.closed.Load() || self.sender.IsClosed()
}

// Close removes this path's mux registration. It does not close the underlying
// router channel, which is shared with other conns.
func (self *RouterChannelPath) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		self.mux.RemoveByConnId(self.connId)
	}
	return nil
}

// --- RouterPath implementation ---

func (self *RouterChannelPath) WireConnId() uint32 {
	return self.connId
}

func (self *RouterChannelPath) GetControlSender() channel.Sender {
	return self.ctrlSender
}

func (self *RouterChannelPath) ChannelLabel() string {
	return self.channelLabel
}

// --- edge.MsgSink implementation (this path's mux registration) ---

// Id returns the wire connId this path is registered under in its router's
// conn mux. This is the mux dispatch key, distinct from the owning conn's
// local diagnostic id.
func (self *RouterChannelPath) Id() uint32 {
	return self.connId
}

// AcceptMessage delivers an inbound message from this path's router to the
// owning conn, identifying this path as the arrival route.
func (self *RouterChannelPath) AcceptMessage(msg *channel.Message, ch edge.SdkChannel) {
	self.conn.acceptPathMessage(self, msg, ch)
}

// HandleMuxClose is invoked when this path's router channel closes. It marks
// the path closed and signals path loss to the conn, which applies the
// pathless policy (survive on other paths, hold for recovery, or tear down).
func (self *RouterChannelPath) HandleMuxClose() error {
	self.closed.Store(true)
	self.conn.onPathClosed(self)
	return nil
}

func (self *RouterChannelPath) GetData() any {
	return self.conn.GetData()
}

func (self *RouterChannelPath) SetData(data any) {
	self.conn.SetData(data)
}

// InspectSink reports this path's mux registration, identified by its wire connId.
func (self *RouterChannelPath) InspectSink() *inspect.VirtualConnDetail {
	return self.conn.edgeConnBase.InspectSink(self.connId)
}

// GetCircuitDetail reports the owning conn's circuit as seen via this path:
// the wire connId, address and ctrl id are this path's router-assigned values.
func (self *RouterChannelPath) GetCircuitDetail() *xgress.CircuitDetail {
	detail := &xgress.CircuitDetail{
		CircuitId: self.conn.circuitId,
		ConnId:    self.connId,
		IsXgress:  true,
		Address:   string(self.xgressAddress),
		CtrlId:    self.xgressCtrlId,
	}
	if xg := self.conn.xg; xg != nil {
		detail.Originator = xg.Originator().String()
	}
	return detail
}
