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

package edge

import (
	"testing"
	"time"

	"github.com/openziti/channel/v4"
	"github.com/stretchr/testify/require"
)

// replyCapturingChannel records what the SDK sends back to the router.
//
// It embeds channel.Channel rather than channel.MultiChannel deliberately: the refusal path
// looks for a control sender by asserting MultiChannel, and failing that assertion is what
// makes it fall back to sending on the channel itself, where Send records the message.
type replyCapturingChannel struct {
	channel.Channel
	sent chan *channel.Message
}

func (ch *replyCapturingChannel) Send(s channel.Sendable) error {
	// Sendable is an envelope wrapper once a timeout is attached, so take the message
	// off it rather than type-asserting to *channel.Message.
	select {
	case ch.sent <- s.Msg():
	default:
	}
	return nil
}

func (ch *replyCapturingChannel) TrySend(s channel.Sendable) (bool, error) {
	return true, ch.Send(s)
}

func (ch *replyCapturingChannel) IsClosed() bool { return false }
func (ch *replyCapturingChannel) Label() string  { return "test" }

// Test_DialForUnknownConnIsAnswered pins the contract the router depends on: a dial
// for a conn the SDK no longer hosts must be answered, not dropped.
//
// A hosted listener can close while its terminator is still selectable at the
// controller, so the router will forward dials for it. The router waits for a reply
// with a route timeout longer than the dialing client's connect timeout, so silence
// here surfaces to the client as a connect timeout rather than a fast, retriable
// failure.
func Test_DialForUnknownConnIsAnswered(t *testing.T) {
	req := require.New(t)

	mux := NewChannelConnMapMux[any](nil)
	ch := &replyCapturingChannel{sent: make(chan *channel.Message, 4)}

	// a dial addressed to a conn id the mux has never heard of, which is what the
	// router sends once the hosting listener has gone away
	const goneConnId = uint32(42)
	req.False(mux.HasConn(goneConnId), "test requires the conn to be absent")

	dial := newMsg(ContentTypeDial, goneConnId, []byte("some-session-token"))
	dial.PutUint32Header(ConnIdHeader, goneConnId)

	// a distinctive sequence, since an uncorrelated reply reports the unset default of -1 and
	// would otherwise satisfy a correlation check against a freshly built message
	const dialSeq = int32(1234)
	dial.SetSequence(dialSeq)

	mux.HandleReceive(dial, ch)

	select {
	case reply := <-ch.sent:
		req.Equal(ContentTypeDialFailed, reply.ContentType,
			"a dial for an unknown conn should be refused, not accepted")
		req.True(reply.IsReplyingTo(dialSeq),
			"the refusal must be correlated to the dial; the router keys its route-timeout wait on "+
				"replyFor, so an uncorrelated reply leaves it waiting exactly as silence would")
		connId, ok := reply.GetUint32Header(ConnIdHeader)
		req.True(ok, "the refusal must carry a conn id")
		req.Equal(goneConnId, connId, "the refusal must name the conn that was dialed")
	case <-time.After(2 * time.Second):
		req.Fail("no reply sent for a dial addressed to an unknown conn id; " +
			"the router will wait out its route timeout and the dialing client will see a connect timeout")
	}
}
