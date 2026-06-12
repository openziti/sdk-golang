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
	"testing"

	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// recordingSink captures accepted messages for assertions.
type recordingSink struct {
	id   uint32
	msgs []*channel.Message
	data any
}

func (r *recordingSink) Id() uint32 { return r.id }
func (r *recordingSink) AcceptMessage(msg *channel.Message, _ edge.SdkChannel) {
	r.msgs = append(r.msgs, msg)
}
func (r *recordingSink) HandleMuxClose() error { return nil }
func (r *recordingSink) GetData() any          { return r.data }
func (r *recordingSink) SetData(data any)      { r.data = data }

func dataMsg(connId uint32, body string) *channel.Message {
	msg := channel.NewMessage(edge.ContentTypeData, []byte(body))
	msg.PutUint32Header(edge.ConnIdHeader, connId)
	return msg
}

// TestPendingSinkBuffersAndReplaysInOrder pins the buffering contract: messages
// accepted before the delegate is installed are replayed to it in arrival order,
// and later messages forward directly.
func TestPendingSinkBuffersAndReplaysInOrder(t *testing.T) {
	req := require.New(t)
	pending := newPendingMsgSink(7)

	pending.AcceptMessage(dataMsg(7, "first"), nil)
	pending.AcceptMessage(dataMsg(7, "second"), nil)

	rec := &recordingSink{id: 7}
	pending.delegateTo(rec)
	req.Len(rec.msgs, 2)
	req.Equal("first", string(rec.msgs[0].Body))
	req.Equal("second", string(rec.msgs[1].Body))

	pending.AcceptMessage(dataMsg(7, "third"), nil)
	req.Len(rec.msgs, 3, "post-delegate messages forward directly")
	req.Equal("third", string(rec.msgs[2].Body))
}

// TestPendingSinkDataTransparency pins the context-data contract: data set on the
// placeholder during establishment transfers to the delegate, data the delegate
// already holds is not clobbered by an empty placeholder, and Get/SetData after
// the handoff operate on the delegate.
func TestPendingSinkDataTransparency(t *testing.T) {
	req := require.New(t)

	// data set during the pending window transfers on handoff
	pending := newPendingMsgSink(7)
	pending.SetData("set-while-pending")
	rec := &recordingSink{id: 7}
	pending.delegateTo(rec)
	req.Equal("set-while-pending", rec.GetData())
	req.Equal("set-while-pending", pending.GetData(), "post-handoff reads come from the delegate")

	// an empty placeholder must not clobber data the delegate already holds
	pending = newPendingMsgSink(8)
	rec = &recordingSink{id: 8}
	rec.SetData("set-at-construction")
	pending.delegateTo(rec)
	req.Equal("set-at-construction", rec.GetData())

	// post-handoff writes land on the delegate
	pending.SetData("set-after-handoff")
	req.Equal("set-after-handoff", rec.GetData())
}

// TestDialEarlyDataNotDropped pins the dial-race fix at the mux level: data
// arriving for a dialing conn id after the dial request is sent but before the
// connection is built (e.g. the hosting side's e2e crypto header) must be
// buffered by the pre-registered pending sink and delivered to the built conn in
// order, not dropped by the mux. Without the pending sink this sequence loses
// the first message, which surfaced as "failed to receive crypto header bytes".
func TestDialEarlyDataNotDropped(t *testing.T) {
	req := require.New(t)
	mux := edge.NewChannelConnMapMux[any](nil)

	connId := mux.GetNextId()

	// as in Connect: register the pending sink, then "send" the dial request
	pending := newPendingMsgSink(connId)
	req.NoError(mux.Add(pending))

	// the hosting side's crypto header arrives before the dialer builds the conn
	mux.(interface {
		HandleReceive(*channel.Message, channel.Channel)
	}).HandleReceive(dataMsg(connId, "crypto-header"), nil)

	// the dialer resumes, builds the conn, and takes over the pending sink
	conn := &recordingSink{id: connId}
	pending.delegateTo(conn)
	req.NoError(mux.Replace(conn))

	// subsequent data routes directly to the conn
	mux.(interface {
		HandleReceive(*channel.Message, channel.Channel)
	}).HandleReceive(dataMsg(connId, "payload"), nil)

	req.Len(conn.msgs, 2, "early data must be delivered, not dropped")
	req.Equal("crypto-header", string(conn.msgs[0].Body), "the first chunk must be the crypto header")
	req.Equal("payload", string(conn.msgs[1].Body))
}
