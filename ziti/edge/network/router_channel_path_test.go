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
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// testRouterSender captures sent messages so tests can assert on what a
// RouterChannelPath puts on the wire.
type testRouterSender struct {
	payloads []*channel.Message
	acks     []*channel.Message
	controls []*channel.Message
	closed   bool
}

func (s *testRouterSender) SendPayload(msg *channel.Message, _ context.Context) error {
	s.payloads = append(s.payloads, msg)
	return nil
}

func (s *testRouterSender) TrySendPayload(msg *channel.Message) (bool, error) {
	s.payloads = append(s.payloads, msg)
	return true, nil
}

func (s *testRouterSender) SendAcknowledgement(msg *channel.Message) error {
	s.acks = append(s.acks, msg)
	return nil
}

func (s *testRouterSender) SendControlMessage(msg *channel.Message) error {
	s.controls = append(s.controls, msg)
	return nil
}

func (s *testRouterSender) IsClosed() bool {
	return s.closed
}

func TestRouterChannelPathIdentity(t *testing.T) {
	req := require.New(t)

	path := &RouterChannelPath{
		conn:          &edgeConnXgress{localId: nextLocalConnId()},
		sender:        &testRouterSender{},
		connId:        1 << 30,
		routerId:      "router-1",
		channelLabel:  "ch:router-1",
		xgressAddress: xgress.Address("addr-1"),
		xgressCtrlId:  "ctrl-1",
	}

	req.Equal(PathTypeRouterChannel, path.Type())
	req.Equal("router-1", path.ID())
	req.Equal(xgress.Address("addr-1"), path.XgressAddress())
	req.Equal("ctrl-1", path.XgressCtrlId())
	req.EqualValues(1<<30, path.WireConnId())
	req.Equal("ch:router-1", path.ChannelLabel())

	// the conn's local diagnostic id is independent of the path's wire connId
	req.NotEqual(path.conn.Id(), path.WireConnId())
}

func TestRouterChannelPathMetrics(t *testing.T) {
	req := require.New(t)

	path := &RouterChannelPath{routerId: "router-1", sender: &testRouterSender{}}

	// no samples yet
	req.EqualValues(0, path.Rtt())
	req.EqualValues(0, path.LossCount())

	// first sample seeds the EWMA directly; later samples are halved toward it
	path.RecordRtt(100)
	req.EqualValues(100, path.Rtt())
	path.RecordRtt(200)
	req.EqualValues(150, path.Rtt()) // (200 + 100) / 2
	path.RecordRtt(150)
	req.EqualValues(150, path.Rtt()) // (150 + 150) / 2

	path.RecordLoss()
	path.RecordLoss()
	req.EqualValues(2, path.LossCount())

	// metrics surface in inspect output
	detail := path.InspectDetail().(*RouterChannelPathDetail)
	req.EqualValues(150, detail.RttMillis)
	req.EqualValues(2, detail.LossCount)
}

func TestRouterChannelPathMuxRegistration(t *testing.T) {
	req := require.New(t)

	mux := edge.NewChannelConnMapMux[any](nil)
	conn := &edgeConnXgress{localId: nextLocalConnId()}
	path := &RouterChannelPath{
		conn:   conn,
		sender: &testRouterSender{},
		connId: 1 << 30,
		mux:    mux,
	}

	// registration is keyed by the path's wire connId, not the conn's local id
	req.NoError(path.register())
	req.True(mux.HasConn(path.WireConnId()))
	req.False(mux.HasConn(conn.Id()))

	// close removes the registration without touching the shared transport,
	// and is idempotent
	req.False(path.IsClosed())
	req.NoError(path.Close())
	req.False(mux.HasConn(path.WireConnId()))
	req.True(path.IsClosed())
	req.NoError(path.Close())
}

func TestRouterChannelPathForwarding(t *testing.T) {
	req := require.New(t)

	sender := &testRouterSender{}
	path := &RouterChannelPath{
		conn:   &edgeConnXgress{localId: nextLocalConnId()},
		sender: sender,
		connId: 1 << 30,
	}

	payload := &xgress.Payload{CircuitId: "circuit-1", Sequence: 1, Data: []byte("hello")}
	req.NoError(path.ForwardPayload(payload, context.Background()))
	req.Len(sender.payloads, 1)
	// payloads are routed by circuit id; no per-conn wire header is stamped
	_, hasConnId := sender.payloads[0].GetUint32Header(edge.ConnIdHeader)
	req.False(hasConnId)

	req.NoError(path.RetransmitPayload("addr-1", payload))
	req.Len(sender.payloads, 2)

	ack := xgress.NewAcknowledgement("circuit-1", xgress.Initiator)
	req.NoError(path.ForwardAcknowledgement(ack, "addr-1"))
	req.Len(sender.acks, 1)

	ctrl := &xgress.Control{Type: xgress.ControlTypeTraceRoute, CircuitId: "circuit-1", Headers: channel.Headers{}}
	req.NoError(path.ForwardControlMessage(ctrl))
	req.Len(sender.controls, 1)

	// a closed sender marks the path closed
	sender.closed = true
	req.True(path.IsClosed())
}
