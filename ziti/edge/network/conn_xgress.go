/*
	Copyright 2019 NetFoundry Inc.

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
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/foundation/v2/info"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream/kx"
	"github.com/sirupsen/logrus"
)

var _ edge.Conn = &edgeConnXgress{}
var _ edgeConnOps = &edgeConnXgress{}

// edgeConnXgress is an edge connection using xgress flow control. It is used
// for both V1 dials that negotiated SDK-side xgress and for V2 dials (which
// are xgress-only). It embeds edgeConnBase for shared state.
type edgeConnXgress struct {
	edgeConnBase
	xgAdapter     *XgAdapter
	xg            *xgress.Xgress
	writeAdapter  *xgress.WriteAdapter
	readAdapter   *xgress.ReadAdapter
	connId        uint32
	defaultSender channel.Sender
	routerId      string
	channelLabel  string
}

// --- edgeConnOps implementation ---

func (conn *edgeConnXgress) Id() uint32 {
	return conn.connId
}

// readSource supplies the chunk reader with the xgress read adapter as the
// chunk source. V2 only ever runs in xgress mode.
func (conn *edgeConnXgress) readSource() ([]byte, uint32, error) {
	return readXgressChunk(conn.readAdapter)
}

// initChunkReader wires up the chunk reader with this conn's source and
// logger. Must be called before the first Read.
func (conn *edgeConnXgress) initChunkReader() {
	conn.chunkReader = newEdgeChunkReader(conn.readSource, func() *logrus.Entry {
		return pfxlog.Logger().
			WithField("connId", conn.Id()).
			WithField("marker", conn.marker).
			WithField("circuitId", conn.circuitId)
	})
}

func (conn *edgeConnXgress) DataSink() io.Writer {
	return conn.writeAdapter
}

func (conn *edgeConnXgress) CloseConn(_ *edgeConnBase, _ bool) {
	// cancel any pending writes
	_ = conn.writeAdapter.SetWriteDeadline(time.Now())

	// if we're using xgress, wait to remove the connection from the mux until the xgress closes,
	// otherwise it becomes unroutable.
	conn.xg.PeerClosed()
}

func (conn *edgeConnXgress) GetDelegateState() map[string]any {
	if conn.xg != nil {
		return map[string]any{
			"xg": conn.xg.GetInspectDetail(true),
		}
	}
	return nil
}

func (conn *edgeConnXgress) HandleInspectConn(base *edgeConnBase, requestedValues []string, resp *inspect.SdkInspectResponse) {
	for _, requested := range requestedValues {
		lc := strings.ToLower(requested)
		if strings.HasPrefix(lc, "circuit:") {
			circuitId := requested[len("circuit:"):]
			if base.circuitId == circuitId {
				detail := conn.xg.GetInspectDetail(false)
				resp.Values[requested] = detail
			}
		} else if strings.HasPrefix(lc, "circuitandstacks:") {
			circuitId := requested[len("circuitAndStacks:"):]
			if base.circuitId == circuitId {
				detail := conn.xg.GetInspectDetail(true)
				resp.Values[requested] = detail
			}
		}
	}
}

func (conn *edgeConnXgress) SendTraceRoute(connId uint32, hops uint32, timeout time.Duration) (*channel.Message, error) {
	msg := edge.NewTraceRouteMsg(connId, hops, uint64(info.NowInMilliseconds()))
	return msg.WithTimeout(timeout).SendForReply(conn.defaultSender)
}

// --- Direct methods ---

func (conn *edgeConnXgress) TraceMsg(string, *channel.Message) {
	// no-op for xgress mode
}

func (conn *edgeConnXgress) Peers() []string {
	return []string{"r/" + conn.routerId}
}

func (conn *edgeConnXgress) RemoteAddr() net.Addr {
	return &xgressAddr{connId: conn.connId, routerId: conn.routerId, label: conn.channelLabel}
}

func (conn *edgeConnXgress) Read(p []byte) (int, error) {
	return conn.doRead(p, conn)
}

func (conn *edgeConnXgress) Write(data []byte) (int, error) {
	return conn.doWrite(data, conn)
}

func (conn *edgeConnXgress) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn v2")
	conn.doClose(true, conn)
	return nil
}

func (conn *edgeConnXgress) close(notifyCtrl bool) {
	conn.doClose(notifyCtrl, conn)
}

func (conn *edgeConnXgress) CloseWrite() error {
	if conn.sentFIN.CompareAndSwap(false, true) {
		conn.xg.CloseRxTimeout()
		return nil
	}
	return nil
}

func (conn *edgeConnXgress) InspectSink() *inspect.VirtualConnDetail {
	return conn.edgeConnBase.InspectSink(conn.Id())
}

func (conn *edgeConnXgress) Inspect() string {
	return conn.edgeConnBase.Inspect(conn.Id())
}

func (conn *edgeConnXgress) GetState() string {
	return conn.doGetState(conn.Id(), conn)
}

func (conn *edgeConnXgress) HandleConnInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleConnInspect(conn.Id(), msg, ch)
}

func (conn *edgeConnXgress) handleTraceRoute(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleTraceRoute(msg, ch)
}

func (conn *edgeConnXgress) HandleInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleInspect(conn.Id(), conn, msg, ch)
}

func (conn *edgeConnXgress) GetCircuitDetail() *xgress.CircuitDetail {
	detail := &xgress.CircuitDetail{
		CircuitId: conn.circuitId,
		ConnId:    conn.Id(),
		IsXgress:  true,
	}
	if conn.xg != nil {
		detail.Originator = conn.xg.Originator().String()
		detail.Address = string(conn.xg.Address())
		detail.CtrlId = conn.xg.CtrlId()
	}
	return detail
}

func (conn *edgeConnXgress) String() string {
	return fmt.Sprintf("zitiConnXgress connId=%v svcId=%v sourceIdentity=%v", conn.Id(), conn.serviceName, conn.sourceIdentity)
}

func (conn *edgeConnXgress) LocalAddr() net.Addr {
	return conn
}

func (conn *edgeConnXgress) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConnXgress) SetWriteDeadline(t time.Time) error {
	return conn.writeAdapter.SetWriteDeadline(t)
}

func (conn *edgeConnXgress) SetReadDeadline(t time.Time) error {
	return conn.readAdapter.SetReadDeadline(t)
}

func (conn *edgeConnXgress) HandleMuxClose() error {
	conn.doClose(false, conn)
	// If the channel is closed, stop the send buffer as we can't rtx anything anyway
	conn.xg.Close()
	return nil
}

func (conn *edgeConnXgress) HandleClose(channel.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.doClose(false, conn)
	conn.xg.CloseSendBuffer()
}

func (conn *edgeConnXgress) CompleteAcceptSuccess() error {
	return conn.edgeConnBase.CompleteAcceptSuccess(conn.Id(), conn)
}

func (conn *edgeConnXgress) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	return conn.doTraceRoute(conn, hops, timeout)
}

func (conn *edgeConnXgress) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	return conn.doEstablishClientCrypto(keypair, peerKey, method, conn)
}

// AcceptMessage handles incoming messages for V2 xgress connections.
func (conn *edgeConnXgress) AcceptMessage(msg *channel.Message, ch edge.SdkChannel) {
	conn.TraceMsg("AcceptMessage", msg)

	switch msg.ContentType {
	case edge.ContentTypeConnInspectRequest:
		go conn.HandleConnInspect(msg, ch)

	case edge.ContentTypeXgPayload:
		payload, err := xgress.UnmarshallPayload(msg)
		if err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error unmarshalling payload")
			conn.xg.Close()
			return
		}

		if err = conn.xg.SendPayload(payload, 0, 0); err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error accepting payload")
			conn.xg.Close()
		}

	case edge.ContentTypeXgAcknowledgement:
		ack, err := xgress.UnmarshallAcknowledgement(msg)
		if err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error unmarshalling acknowledgement")
			conn.xg.Close()
			return
		}

		if err = conn.xg.SendAcknowledgement(ack); err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error accepting acknowledgement")
			conn.xg.Close()
		}

	case edge.ContentTypeStateClosed:
		if conn.IsClosed() {
			return
		}
		// routing is not accepting more data, so we need to close the send buffer
		go conn.xg.CloseSendBuffer()
		conn.xg.CloseXgToClient()
		conn.sentFIN.Store(true) // if we're not closing until all reads are done, at least prevent more writes

	case edge.ContentTypeInspectRequest:
		go conn.HandleInspect(msg, ch)

	case edge.ContentTypeTraceRoute:
		go conn.handleTraceRoute(msg, ch)
	}
}

// setupXgressFlowControl sets up the xgress adapters and starts the xgress.
// The caller is responsible for registering this conn in the mux after a
// successful return.
func (conn *edgeConnXgress) setupXgressFlowControl(msg *channel.Message, originator xgress.Originator,
	envF func() xgress.Env, ch edge.SdkChannel, mux edge.ConnMux[any]) error {

	ctrlId, ok := msg.GetStringHeader(edge.XgressCtrlIdHeader)
	if !ok {
		_ = conn.Close()
		return fmt.Errorf("xgress conn id header not found for circuit %s", conn.circuitId)
	}
	addr, ok := msg.GetStringHeader(edge.XgressAddressHeader)
	if !ok {
		_ = conn.Close()
		return fmt.Errorf("xgress address header not found for circuit %s", conn.circuitId)
	}

	msgCh := edge.NewEdgeMsgChannel(ch, conn.Id())
	sender := newRouterSender(*msgCh)
	xgAdapter := &XgAdapter{
		sender:     sender,
		connId:     conn.Id(),
		circuitId:  conn.circuitId,
		mux:        mux,
		muxSink:    conn,
		ctrlSender: ch.GetControlSender(),
		env:        envF(),
	}

	xg := xgress.NewXgress(conn.circuitId, ctrlId, xgress.Address(addr), xgAdapter, originator, xgress.DefaultOptions(), nil)
	xgAdapter.xg = xg
	xgAdapter.writeAdapter = xg.NewWriteAdapter()
	readAdapter := xg.NewReadAdapter()
	xg.AddCloseHandler(xgAdapter)

	xg.SetDataPlaneAdapter(xgAdapter)
	xg.Start()

	conn.xgAdapter = xgAdapter
	conn.xg = xg
	conn.writeAdapter = xgAdapter.writeAdapter
	conn.readAdapter = readAdapter
	conn.defaultSender = msgCh.GetDefaultSender()
	conn.routerId = ch.GetChannel().Id()
	conn.channelLabel = ch.GetChannel().LogicalName()

	return nil
}
