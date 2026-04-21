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
	pkgerrors "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var _ edge.Conn = &edgeConnXgress{}

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

func (conn *edgeConnXgress) Write(data []byte) (int, error) {
	return conn.writeTo(data, conn.writeAdapter)
}

func (conn *edgeConnXgress) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn xgress")
	conn.close(true)
	return nil
}

// close performs the full close sequence for an xgress conn: atomic close
// flip, propagate FIN, cancel pending writes, and signal the xgress that the
// peer is closed. The mux entry is not removed here — xgress tear-down removes
// it once the xgress actually finishes, so in-flight payloads stay routable.
func (conn *edgeConnXgress) close(_ bool) {
	if !conn.beginClose() {
		return
	}
	log := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	log.Debug("close: begin")
	defer log.Debug("close: end")

	_ = conn.writeAdapter.SetWriteDeadline(time.Now())
	conn.xg.PeerClosed()
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

// Inspect returns a JSON snapshot of this xgress connection's state. circuitId
// (included via baseState) is the primary identifier; connId is emitted as a
// diagnostic for correlating with edge-channel logs.
func (conn *edgeConnXgress) Inspect() string {
	state := conn.baseState()
	state["connId"] = conn.Id()
	return marshalState(state)
}

// GetState returns a JSON dump of this connection's state, including the
// xgress inspect detail when an xg is attached.
func (conn *edgeConnXgress) GetState() string {
	state := conn.baseState()
	state["connId"] = conn.Id()
	if conn.xg != nil {
		state["xg"] = conn.xg.GetInspectDetail(true)
	}
	return marshalState(state)
}

// HandleConnInspect replies to a ContentTypeConnInspectRequest with the JSON
// state from Inspect.
func (conn *edgeConnXgress) HandleConnInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.edgeConnBase.HandleConnInspect(conn.Id(), conn.Inspect(), msg, ch)
}

// handleTraceRouteControl handles an incoming xgress trace route request as
// the terminator of a circuit. The request arrives wrapped in an edge
// ContentTypeXgControl message; we respond with a ControlTypeTraceRouteResponse
// and promote ControlUserVal to ReplyForHeader so the dialer's SendForReply
// correlates through the fabric.
func (conn *edgeConnXgress) handleTraceRouteControl(ctrl *xgress.Control, ch edge.SdkChannel) {
	resp := ctrl.CreateTraceResponse("sdk/golang", "")
	respMsg := resp.Marshall()
	respMsg.PutUint32Header(edge.ConnIdHeader, conn.Id())
	if userVal, ok := ctrl.Headers.GetUint32Header(xgress.ControlUserVal); ok {
		respMsg.PutUint32Header(channel.ReplyForHeader, userVal)
	}
	if err := ch.GetControlSender().Send(respMsg); err != nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).
			Error("failed to send xgress trace route response")
	}
}

// HandleInspect replies to a ContentTypeInspectRequest. Supports the
// "circuit:<id>" and "circuitAndStacks:<id>" inspect keys by returning the
// xgress inspect detail when the requested circuit matches this conn.
func (conn *edgeConnXgress) HandleInspect(msg *channel.Message, ch edge.SdkChannel) {
	resp := &inspect.SdkInspectResponse{
		Success: true,
		Values:  make(map[string]any),
	}
	requestedValues, _, err := msg.GetStringSliceHeader(edge.InspectRequestValuesHeader)
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
		resp.Success = false
		sendInspectReply(conn.Id(), msg, ch, resp)
		return
	}
	for _, requested := range requestedValues {
		lc := strings.ToLower(requested)
		if strings.HasPrefix(lc, "circuit:") {
			circuitId := requested[len("circuit:"):]
			if conn.circuitId == circuitId && conn.xg != nil {
				resp.Values[requested] = conn.xg.GetInspectDetail(false)
			}
		} else if strings.HasPrefix(lc, "circuitandstacks:") {
			circuitId := requested[len("circuitAndStacks:"):]
			if conn.circuitId == circuitId && conn.xg != nil {
				resp.Values[requested] = conn.xg.GetInspectDetail(true)
			}
		}
	}
	sendInspectReply(conn.Id(), msg, ch, resp)
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
	conn.close(false)
	// If the channel is closed, stop the send buffer as we can't rtx anything anyway
	conn.xg.Close()
	return nil
}

func (conn *edgeConnXgress) HandleClose(channel.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.close(false)
	conn.xg.CloseSendBuffer()
}

func (conn *edgeConnXgress) CompleteAcceptSuccess() error {
	return conn.edgeConnBase.CompleteAcceptSuccess(conn.Id(), conn.close)
}

// TraceRoute initiates a trace route from this xgress conn. Uses the
// circuit-id-keyed xgress.Control protocol wrapped in ContentTypeXgControl
// edge messages, so trace traverses the fabric via the existing forwarder
// control path rather than the edge mux's connId routing.
func (conn *edgeConnXgress) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	ts := uint64(info.NowInMilliseconds())
	ctrl := &xgress.Control{
		Type:      xgress.ControlTypeTraceRoute,
		CircuitId: conn.circuitId,
		Headers:   channel.Headers{},
	}
	ctrl.Headers.PutUint32Header(xgress.ControlHopCount, hops)
	ctrl.Headers.PutUint64Header(xgress.ControlTimestamp, ts)

	msg := ctrl.Marshall()
	msg.PutUint32Header(edge.ConnIdHeader, conn.Id())

	resp, err := msg.WithTimeout(timeout).SendForReply(conn.defaultSender)
	if err != nil {
		return nil, err
	}
	if resp.ContentType != edge.ContentTypeXgControl {
		return nil, pkgerrors.Errorf("unexpected response content type: %v", resp.ContentType)
	}

	respCtrl, err := xgress.UnmarshallControl(resp)
	if err != nil {
		return nil, pkgerrors.Wrap(err, "failed to unmarshal trace route response control")
	}
	if !respCtrl.IsTypeTraceRouteResponse() {
		return nil, pkgerrors.Errorf("unexpected control type in response: %v", respCtrl.Type)
	}

	respHops, _ := respCtrl.Headers.GetUint32Header(xgress.ControlHopCount)
	respTs, _ := respCtrl.Headers.GetUint64Header(xgress.ControlTimestamp)
	elapsed := time.Duration(0)
	if respTs > 0 {
		elapsed = time.Duration(info.NowInMilliseconds()-int64(respTs)) * time.Millisecond
	}
	hopType, _ := respCtrl.Headers.GetStringHeader(xgress.ControlHopType)
	hopId, _ := respCtrl.Headers.GetStringHeader(xgress.ControlHopId)
	hopErr, _ := respCtrl.Headers.GetStringHeader(xgress.ControlError)

	return &edge.TraceRouteResult{
		Hops:    respHops,
		Time:    elapsed,
		HopType: hopType,
		HopId:   hopId,
		Error:   hopErr,
	}, nil
}

func (conn *edgeConnXgress) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	if err := conn.establishClientCryptoTo(keypair, peerKey, method, conn.writeAdapter); err != nil {
		return err
	}

	pfxlog.Logger().
		WithField("circuitId", conn.circuitId).
		WithField("marker", conn.marker).
		Debug("crypto established")

	return nil
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

	case edge.ContentTypeXgControl:
		ctrl, err := xgress.UnmarshallControl(msg)
		if err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("failed to unmarshal xgress control")
			return
		}
		if ctrl.IsTypeTraceRoute() {
			go conn.handleTraceRouteControl(ctrl, ch)
		}
		// ControlTypeTraceRouteResponse arrives only as a reply to a SendForReply
		// we initiated; the channel layer delivers it directly to that waiter, so
		// we never see it here.
	}
}

// setupXgressFlowControl sets up the xgress adapters and starts the xgress.
// The caller is responsible for registering this conn in the mux after a
// successful return.
func (conn *edgeConnXgress) setupXgressFlowControl(msg *channel.Message, originator xgress.Originator,
	envF func() xgress.Env, ch edge.SdkChannel, mux edge.ConnMux[any]) error {

	// On header-validation failures here, there is nothing to clean up: the conn
	// has no xgress, no write adapter, and is not yet registered in the mux.
	// Calling Close() would NPE on the nil xg/writeAdapter.
	ctrlId, ok := msg.GetStringHeader(edge.XgressCtrlIdHeader)
	if !ok {
		return fmt.Errorf("xgress conn id header not found for circuit %s", conn.circuitId)
	}
	addr, ok := msg.GetStringHeader(edge.XgressAddressHeader)
	if !ok {
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
