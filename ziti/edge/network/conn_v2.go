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
	"context"
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
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var _ edge.Conn = &edgeConnV2{}
var _ edgeConnOps = &edgeConnV2{}

// edgeConnV2 represents an individual V2 connection in the Ziti edge network.
// It embeds edgeConnBase for shared state and always uses xgress flow control.
// Unlike edgeConn, it never falls back to legacy mode.
type edgeConnV2 struct {
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

func (conn *edgeConnV2) Id() uint32 {
	return conn.connId
}

// readSource supplies the chunk reader with the xgress read adapter as the
// chunk source. V2 only ever runs in xgress mode.
func (conn *edgeConnV2) readSource() ([]byte, uint32, error) {
	return readXgressChunk(conn.readAdapter)
}

// initChunkReader wires up the chunk reader with this conn's source and
// logger. Must be called before the first Read.
func (conn *edgeConnV2) initChunkReader() {
	conn.chunkReader = newEdgeChunkReader(conn.readSource, func() *logrus.Entry {
		return pfxlog.Logger().
			WithField("connId", conn.Id()).
			WithField("marker", conn.marker).
			WithField("circuitId", conn.circuitId)
	})
}

func (conn *edgeConnV2) DataSink() io.Writer {
	return conn.writeAdapter
}

func (conn *edgeConnV2) CloseConn(_ *edgeConnBase, _ bool) {
	// cancel any pending writes
	_ = conn.writeAdapter.SetWriteDeadline(time.Now())

	// if we're using xgress, wait to remove the connection from the mux until the xgress closes,
	// otherwise it becomes unroutable.
	conn.xg.PeerClosed()
}

func (conn *edgeConnV2) GetDelegateState() map[string]any {
	if conn.xg != nil {
		return map[string]any{
			"xg": conn.xg.GetInspectDetail(true),
		}
	}
	return nil
}

func (conn *edgeConnV2) HandleInspectConn(base *edgeConnBase, requestedValues []string, resp *inspect.SdkInspectResponse) {
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

func (conn *edgeConnV2) SendTraceRoute(connId uint32, hops uint32, timeout time.Duration) (*channel.Message, error) {
	msg := edge.NewTraceRouteMsg(connId, hops, uint64(info.NowInMilliseconds()))
	return msg.WithTimeout(timeout).SendForReply(conn.defaultSender)
}

// --- Direct methods ---

func (conn *edgeConnV2) TraceMsg(string, *channel.Message) {
	// no-op for xgress mode
}

func (conn *edgeConnV2) Peers() []string {
	return []string{"r/" + conn.routerId}
}

func (conn *edgeConnV2) RemoteAddr() net.Addr {
	return &xgressAddr{connId: conn.connId, routerId: conn.routerId, label: conn.channelLabel}
}

func (conn *edgeConnV2) Read(p []byte) (int, error) {
	return conn.doRead(p, conn)
}

func (conn *edgeConnV2) Write(data []byte) (int, error) {
	return conn.doWrite(data, conn)
}

func (conn *edgeConnV2) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn v2")
	conn.doClose(true, conn)
	return nil
}

func (conn *edgeConnV2) close(notifyCtrl bool) {
	conn.doClose(notifyCtrl, conn)
}

func (conn *edgeConnV2) CloseWrite() error {
	if conn.sentFIN.CompareAndSwap(false, true) {
		conn.xg.CloseRxTimeout()
		return nil
	}
	return nil
}

func (conn *edgeConnV2) InspectSink() *inspect.VirtualConnDetail {
	return conn.edgeConnBase.InspectSink(conn.Id())
}

func (conn *edgeConnV2) Inspect() string {
	return conn.edgeConnBase.Inspect(conn.Id())
}

func (conn *edgeConnV2) GetState() string {
	return conn.doGetState(conn.Id(), conn)
}

func (conn *edgeConnV2) HandleConnInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleConnInspect(conn.Id(), msg, ch)
}

func (conn *edgeConnV2) handleTraceRoute(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleTraceRoute(msg, ch)
}

func (conn *edgeConnV2) HandleInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleInspect(conn.Id(), conn, msg, ch)
}

func (conn *edgeConnV2) GetCircuitDetail() *xgress.CircuitDetail {
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

func (conn *edgeConnV2) returnInspectResponse(msg *channel.Message, ch edge.SdkChannel, resp *inspect.SdkInspectResponse) {
	conn.doReturnInspectResponse(conn.Id(), msg, ch, resp)
}

func (conn *edgeConnV2) String() string {
	return fmt.Sprintf("zitiConnV2 connId=%v svcId=%v sourceIdentity=%v", conn.Id(), conn.serviceName, conn.sourceIdentity)
}

func (conn *edgeConnV2) LocalAddr() net.Addr {
	return conn
}

func (conn *edgeConnV2) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConnV2) SetWriteDeadline(t time.Time) error {
	return conn.writeAdapter.SetWriteDeadline(t)
}

func (conn *edgeConnV2) SetReadDeadline(t time.Time) error {
	return conn.readAdapter.SetReadDeadline(t)
}

func (conn *edgeConnV2) HandleMuxClose() error {
	conn.doClose(false, conn)
	// If the channel is closed, stop the send buffer as we can't rtx anything anyway
	conn.xg.Close()
	return nil
}

func (conn *edgeConnV2) HandleClose(channel.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.doClose(false, conn)
	conn.xg.CloseSendBuffer()
}

func (conn *edgeConnV2) CompleteAcceptSuccess() error {
	return conn.edgeConnBase.CompleteAcceptSuccess(conn.Id())
}

func (conn *edgeConnV2) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	return conn.doTraceRoute(conn, hops, timeout)
}

func (conn *edgeConnV2) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	return conn.doEstablishClientCrypto(keypair, peerKey, method, conn)
}

// AcceptMessage handles incoming messages for V2 xgress connections.
func (conn *edgeConnV2) AcceptMessage(msg *channel.Message, ch edge.SdkChannel) {
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

// ConnectV2 performs a sessionless dial via the ConnectV2 protocol for V2 connections.
// The router authorizes the dial locally via RDM, so no service session token is required.
// The circuit ID is received early via a route_circuit message before the StateConnected reply.
func (conn *edgeConnV2) ConnectV2(ctx context.Context, serviceId string, identifierType edge.ServiceIdentifierType,
	options *edge.DialOptions, envF func() xgress.Env, routerConn *routerConn) (edge.Conn, error) {

	logger := pfxlog.Logger().
		WithField("marker", conn.marker).
		WithField("connId", conn.Id()).
		WithField("serviceId", serviceId)

	requestId := newMarker() // use same random string generator for the request correlation ID

	pd := routerConn.pendingDials.Register(requestId, conn, routerConn.mux)
	defer routerConn.pendingDials.Remove(requestId)

	var pub []byte
	if conn.crypto {
		pub = conn.keyPair.Public()
	}
	connectRequest := edge.NewConnectV2Msg(conn.Id(), serviceId, identifierType, requestId, pub, options)
	connectRequest.PutStringHeader(edge.ConnectionMarkerHeader, conn.marker)

	conn.TraceMsg("connectv2", connectRequest)
	replyMsg, err := connectRequest.WithContext(ctx).SendForReply(routerConn.ch.GetControlSender())
	if err != nil {
		pd.DialFailed()
		logger.Error(err)
		return nil, err
	}

	if replyMsg.ContentType == edge.ContentTypeStateClosed {
		pd.DialFailed()
		return nil, errors.Errorf("dial failed: %v", string(replyMsg.Body))
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		pd.DialFailed()
		return nil, errors.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
	}

	// Get circuit ID — prefer the one from route_circuit (guaranteed by channel ordering),
	// fall back to the CircuitIdHeader on the reply
	conn.circuitId = pd.GetCircuitId()
	if conn.circuitId == "" {
		conn.circuitId, _ = replyMsg.GetStringHeader(edge.CircuitIdHeader)
	}
	logger = logger.WithField("circuitId", conn.circuitId)

	if stickinessToken, ok := replyMsg.Headers[edge.StickinessTokenHeader]; ok {
		if conn.customState == nil {
			conn.customState = map[int32][]byte{}
		}
		conn.customState[edge.StickinessTokenHeader] = stickinessToken
	}

	if err = conn.setupXgressFlowControl(replyMsg, xgress.Initiator, envF, routerConn.ch, routerConn.mux); err != nil {
		return nil, err
	}

	if conn.crypto {
		method, _ := replyMsg.GetByteHeader(edge.CryptoMethodHeader)
		hostPubKey := replyMsg.Headers[edge.PublicKeyHeader]
		if hostPubKey != nil {
			logger.Debug("setting up end-to-end encryption")
			if err = conn.establishClientCrypto(conn.keyPair, hostPubKey, edge.CryptoMethod(method)); err != nil {
				logger.WithError(err).Error("crypto failure")
				_ = conn.Close()
				return nil, err
			}
			logger.Debug("client tx encryption setup done")
		} else {
			logger.Warn("connection is not end-to-end-encrypted")
		}
	}

	logger.Debug("connected via v2")

	return conn, nil
}

// setupXgressFlowControl sets up xgress-based flow control for V2 connections.
// Unlike edgeConn.setupFlowControl, this always uses xgress mode and never falls back to legacy.
func (conn *edgeConnV2) setupXgressFlowControl(msg *channel.Message, originator xgress.Originator,
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
