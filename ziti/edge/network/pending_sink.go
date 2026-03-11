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

	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
)

// pendingMsgSink buffers messages for a conn id whose connection is still being
// established. It is registered with the mux before the dial request is sent, so
// data that arrives between the router establishing the circuit and the dialing
// goroutine building the connection (e.g. the hosting side's e2e crypto header,
// which it sends the moment it accepts) is queued instead of dropped by the mux.
// Once the connection is built, delegateTo replays the buffer and forwards, and
// the mux entry is replaced with the real sink.
type pendingMsgSink struct {
	id       uint32
	mu       sync.Mutex
	delegate edge.MsgSink[any]
	queued   []pendingMsg
	data     any
}

type pendingMsg struct {
	msg *channel.Message
	ch  edge.SdkChannel
}

func newPendingMsgSink(id uint32) *pendingMsgSink {
	return &pendingMsgSink{id: id}
}

func (sink *pendingMsgSink) Id() uint32 {
	return sink.id
}

// AcceptMessage queues the message, or forwards it if a delegate is installed.
// Forwarding happens under the same lock as the replay in delegateTo, so a message
// racing the handoff cannot overtake the buffered messages.
func (sink *pendingMsgSink) AcceptMessage(msg *channel.Message, ch edge.SdkChannel) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.delegate != nil {
		sink.delegate.AcceptMessage(msg, ch)
		return
	}
	sink.queued = append(sink.queued, pendingMsg{msg: msg, ch: ch})
}

// delegateTo replays any buffered messages to the established connection's sink,
// in arrival order, and forwards everything that arrives afterwards, making the
// placeholder transparent: context data set during establishment transfers to the
// delegate too. The caller should then Replace this sink with the delegate in the
// mux; messages dispatched in between still arrive in order through the
// forwarding path.
func (sink *pendingMsgSink) delegateTo(delegate edge.MsgSink[any]) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, pending := range sink.queued {
		delegate.AcceptMessage(pending.msg, pending.ch)
	}
	sink.queued = nil
	if sink.data != nil { // don't clobber data the delegate set during construction
		delegate.SetData(sink.data)
		sink.data = nil
	}
	sink.delegate = delegate
}

// HandleMuxClose drops the buffer; if establishment already completed, the
// delegate is registered with the mux directly and handles its own close.
func (sink *pendingMsgSink) HandleMuxClose() error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.queued = nil
	return nil
}

func (sink *pendingMsgSink) GetData() any {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.delegate != nil {
		return sink.delegate.GetData()
	}
	return sink.data
}

func (sink *pendingMsgSink) SetData(data any) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.delegate != nil {
		sink.delegate.SetData(data)
		return
	}
	sink.data = data
}
