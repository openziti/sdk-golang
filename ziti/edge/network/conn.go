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
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/info"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream/kx"
	pkgerrors "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var unsupportedCrypto = pkgerrors.New("unsupported crypto")

var _ edge.Conn = &edgeConn{}
var _ edgeConnOps = &edgeConn{}

// edgeConn represents an individual V1 connection in the Ziti edge network.
// It embeds edgeConnBase for shared state and holds both legacy and xgress mode
// fields directly, switching behavior based on the isXgress flag.
type edgeConn struct {
	edgeConnBase

	// Legacy mode fields (always set)
	msgCh edge.MsgChannel
	mux   edge.ConnMux[any]
	readQ *noopSeq[*channel.Message]

	// Xgress mode fields (set by setupFlowControl if xgress mode, nil otherwise)
	xgAdapter    *XgAdapter
	xg           *xgress.Xgress
	writeAdapter *xgress.WriteAdapter
	readAdapter  *xgress.ReadAdapter
	dfltSender   channel.Sender
	routerId     string
	channelLabel string
	isXgress     bool
}

// --- edgeConnOps implementation ---

func (conn *edgeConn) Id() uint32 {
	return conn.msgCh.Id()
}

// readSource dispatches to the appropriate chunk source based on the current
// mode. It is installed on the chunkReader by initChunkReader.
func (conn *edgeConn) readSource() ([]byte, uint32, error) {
	if conn.isXgress {
		return readXgressChunk(conn.readAdapter)
	}
	return conn.readLegacyChunk()
}

func (conn *edgeConn) readLegacyChunk() ([]byte, uint32, error) {
	for {
		msg, err := conn.readQ.GetNext()
		if err != nil {
			return nil, 0, err
		}

		flags, _ := msg.GetUint32Header(edge.FlagsHeader)

		switch msg.ContentType {
		case edge.ContentTypeStateClosed:
			conn.HandleStateClosedInRead(&conn.edgeConnBase)
			continue
		case edge.ContentTypeData:
			return msg.Body, flags, nil
		default:
			pfxlog.Logger().WithField("connId", conn.Id()).
				WithField("type", msg.ContentType).Error("unexpected message in read")
			continue
		}
	}
}

// initChunkReader wires up the chunk reader with this conn's source and
// logger. Must be called before the first Read.
func (conn *edgeConn) initChunkReader() {
	conn.chunkReader = newEdgeChunkReader(conn.readSource, func() *logrus.Entry {
		return pfxlog.Logger().
			WithField("connId", conn.Id()).
			WithField("marker", conn.marker).
			WithField("circuitId", conn.circuitId)
	})
}

func (conn *edgeConn) DataSink() io.Writer {
	if conn.isXgress {
		return conn.writeAdapter
	}
	return &conn.msgCh
}

func (conn *edgeConn) CloseConn(base *edgeConnBase, notifyCtrl bool) {
	if conn.isXgress {
		// cancel any pending writes
		_ = conn.writeAdapter.SetWriteDeadline(time.Now())

		// if we're using xgress, wait to remove the connection from the mux until the xgress closes,
		// otherwise it becomes unroutable.
		conn.xg.PeerClosed()
		return
	}

	// legacy mode
	log := pfxlog.Logger().WithField("connId", int(conn.Id())).WithField("marker", base.marker).WithField("circuitId", base.circuitId)

	if notifyCtrl {
		msg := edge.NewStateClosedMsg(conn.Id(), "")
		if err := conn.msgCh.SendState(msg); err != nil {
			log.WithError(err).Error("failed to send close message")
		}
	}

	conn.mux.RemoveByConnId(conn.Id())
}

func (conn *edgeConn) GetDelegateState() map[string]any {
	if conn.isXgress && conn.xg != nil {
		return map[string]any{
			"xg": conn.xg.GetInspectDetail(true),
		}
	}
	return nil
}

func (conn *edgeConn) HandleInspectConn(base *edgeConnBase, requestedValues []string, resp *inspect.SdkInspectResponse) {
	if !conn.isXgress {
		// no circuit-level inspect data in legacy mode
		return
	}

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

func (conn *edgeConn) SendTraceRoute(connId uint32, hops uint32, timeout time.Duration) (*channel.Message, error) {
	msg := edge.NewTraceRouteMsg(connId, hops, uint64(info.NowInMilliseconds()))
	if conn.isXgress {
		return msg.WithTimeout(timeout).SendForReply(conn.dfltSender)
	}
	return msg.WithTimeout(timeout).SendForReply(conn.msgCh.GetDefaultSender())
}

// --- Direct methods (previously delegated) ---

func (conn *edgeConn) TraceMsg(source string, msg *channel.Message) {
	if conn.isXgress {
		// no-op for xgress mode
		return
	}
	conn.msgCh.TraceMsg(source, msg)
}

func (conn *edgeConn) Peers() []string {
	if conn.isXgress {
		return []string{"r/" + conn.routerId}
	}
	return []string{"r/" + conn.msgCh.GetChannel().Id()}
}

func (conn *edgeConn) RemoteAddr() net.Addr {
	if conn.isXgress {
		return &xgressAddr{connId: conn.Id(), routerId: conn.routerId, label: conn.channelLabel}
	}
	return &edge.Addr{MsgCh: conn.msgCh}
}

func (conn *edgeConn) CloseWrite() error {
	if conn.sentFIN.CompareAndSwap(false, true) {
		if conn.isXgress {
			conn.xg.CloseRxTimeout()
			return nil
		}
		headers := channel.Headers{}
		headers.PutUint32Header(edge.FlagsHeader, edge.FIN)
		_, err := conn.msgCh.WriteTraced(nil, nil, headers)
		return err
	}
	return nil
}

func (conn *edgeConn) SetWriteDeadline(t time.Time) error {
	if conn.isXgress {
		return conn.writeAdapter.SetWriteDeadline(t)
	}
	return conn.msgCh.SetWriteDeadline(t)
}

func (conn *edgeConn) SetReadDeadline(t time.Time) error {
	if conn.isXgress {
		return conn.readAdapter.SetReadDeadline(t)
	}
	conn.readQ.SetReadDeadline(t)
	return nil
}

func (conn *edgeConn) HandleStateClosed() {
	if conn.isXgress {
		// routing is not accepting more data, so we need to close the send buffer
		go conn.xg.CloseSendBuffer()
		conn.xg.CloseXgToClient()
		return
	}
	// no-op for legacy mode; the message falls through to readQ
}

func (conn *edgeConn) HandleStateClosedInRead(base *edgeConnBase) {
	if conn.isXgress {
		log := pfxlog.Logger().WithField("connId", conn.Id()).
			WithField("marker", base.marker).
			WithField("circuitId", base.circuitId)

		base.chunkReader.MarkFIN()
		if base.sentFIN.Load() {
			log.Debug("received ConnState_CLOSED message, fin sent, closing connection")
			base.doClose(false, conn)
		} else {
			log.Debug("received ConnState_CLOSED message, fin not yet sent")
		}
		return
	}

	// legacy mode
	pfxlog.Logger().WithField("connId", conn.Id()).
		WithField("marker", base.marker).
		WithField("circuitId", base.circuitId).
		Debug("received ConnState_CLOSED message, closing connection")
	base.doClose(false, conn)
}

func (conn *edgeConn) HandleMuxClose() error {
	conn.doClose(false, conn)
	if conn.isXgress {
		// If the channel is closed, stop the send buffer as we can't rtx anything anyway
		conn.xg.Close()
	}
	// no additional action needed for legacy mode
	return nil
}

func (conn *edgeConn) HandleClose(channel.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.doClose(false, conn)
	if conn.isXgress {
		conn.xg.CloseSendBuffer()
	}
	// no additional action needed for legacy mode
}

func (conn *edgeConn) HandleXgPayload(base *edgeConnBase, msg *channel.Message) {
	if !conn.isXgress {
		pfxlog.Logger().WithField("circuitId", base.circuitId).Error("received xgress payload on non-xgress connection")
		return
	}

	payload, err := xgress.UnmarshallPayload(msg)
	if err != nil {
		pfxlog.Logger().WithField("circuitId", base.circuitId).WithError(err).Error("error unmarshalling payload")
		conn.xg.Close()
		return
	}

	if err = conn.xg.SendPayload(payload, 0, 0); err != nil {
		pfxlog.Logger().WithField("circuitId", base.circuitId).WithError(err).Error("error accepting payload")
		conn.xg.Close()
	}
}

func (conn *edgeConn) HandleXgAcknowledgement(base *edgeConnBase, msg *channel.Message) {
	if !conn.isXgress {
		pfxlog.Logger().WithField("circuitId", base.circuitId).Error("received xgress ack on non-xgress connection")
		return
	}

	ack, err := xgress.UnmarshallAcknowledgement(msg)
	if err != nil {
		pfxlog.Logger().WithField("circuitId", base.circuitId).WithError(err).Error("error unmarshalling acknowledgement")
		conn.xg.Close()
		return
	}

	if err = conn.xg.SendAcknowledgement(ack); err != nil {
		pfxlog.Logger().WithField("circuitId", base.circuitId).WithError(err).Error("error accepting acknowledgement")
		conn.xg.Close()
	}
}

func (conn *edgeConn) QueueMessage(base *edgeConnBase, msg *channel.Message) {
	if conn.isXgress {
		// no-op: in xgress mode, data arrives via ReadAdapter, not readQ
		return
	}
	if err := conn.readQ.PutSequenced(msg); err != nil {
		logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
			Error("error pushing edge message to sequencer")
	} else {
		logrus.WithFields(edge.GetLoggerFields(msg)).Debugf("received %v bytes (msg type: %v)", len(msg.Body), msg.ContentType)
	}
}

func (conn *edgeConn) GetCircuitDetail() *xgress.CircuitDetail {
	if conn.isXgress {
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
	return &xgress.CircuitDetail{
		CircuitId: conn.circuitId,
		ConnId:    conn.Id(),
	}
}

// --- Standard conn methods ---

func (conn *edgeConn) Read(p []byte) (int, error) {
	return conn.doRead(p, conn)
}

func (conn *edgeConn) Write(data []byte) (int, error) {
	return conn.doWrite(data, conn)
}

func (conn *edgeConn) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn")
	conn.doClose(true, conn)
	return nil
}

func (conn *edgeConn) close(notifyCtrl bool) {
	conn.doClose(notifyCtrl, conn)
}

func (conn *edgeConn) InspectSink() *inspect.VirtualConnDetail {
	return conn.edgeConnBase.InspectSink(conn.Id())
}

func (conn *edgeConn) Inspect() string {
	return conn.edgeConnBase.Inspect(conn.Id())
}

func (conn *edgeConn) GetState() string {
	return conn.doGetState(conn.Id(), conn)
}

func (conn *edgeConn) HandleConnInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleConnInspect(conn.Id(), msg, ch)
}

func (conn *edgeConn) handleTraceRoute(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleTraceRoute(msg, ch)
}

func (conn *edgeConn) HandleInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.doHandleInspect(conn.Id(), conn, msg, ch)
}

func (conn *edgeConn) returnInspectResponse(msg *channel.Message, ch edge.SdkChannel, resp *inspect.SdkInspectResponse) {
	conn.doReturnInspectResponse(conn.Id(), msg, ch, resp)
}

func (conn *edgeConn) String() string {
	return fmt.Sprintf("zitiConn connId=%v svcId=%v sourceIdentity=%v", conn.Id(), conn.serviceName, conn.sourceIdentity)
}

func (conn *edgeConn) LocalAddr() net.Addr {
	return conn
}

func (conn *edgeConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConn) CompleteAcceptSuccess() error {
	return conn.edgeConnBase.CompleteAcceptSuccess(conn.Id())
}

func (conn *edgeConn) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	return conn.doTraceRoute(conn, hops, timeout)
}

func (conn *edgeConn) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	return conn.doEstablishClientCrypto(keypair, peerKey, method, conn)
}

func (conn *edgeConn) AcceptMessage(msg *channel.Message, ch edge.SdkChannel) {
	conn.TraceMsg("AcceptMessage", msg)

	if msg.ContentType == edge.ContentTypeConnInspectRequest {
		go conn.HandleConnInspect(msg, ch)
		return
	}

	switch msg.ContentType {
	case edge.ContentTypeXgPayload:
		conn.HandleXgPayload(&conn.edgeConnBase, msg)
		return

	case edge.ContentTypeXgAcknowledgement:
		conn.HandleXgAcknowledgement(&conn.edgeConnBase, msg)
		return

	case edge.ContentTypeStateClosed:
		if conn.IsClosed() {
			return
		}
		conn.HandleStateClosed()
		conn.sentFIN.Store(true) // if we're not closing until all reads are done, at least prevent more writes

	case edge.ContentTypeInspectRequest:
		go conn.HandleInspect(msg, ch)
		return

	case edge.ContentTypeTraceRoute:
		go conn.handleTraceRoute(msg, ch)
		return
	}

	conn.QueueMessage(&conn.edgeConnBase, msg)
}

func (conn *edgeConn) Connect(ctx context.Context, session *rest_model.SessionDetail, options *edge.DialOptions,
	envF func() xgress.Env, ch edge.SdkChannel, mux edge.ConnMux[any]) (edge.Conn, error) {

	logger := pfxlog.Logger().
		WithField("marker", conn.marker).
		WithField("connId", conn.Id()).
		WithField("sessionId", session.ID)

	var pub []byte
	if conn.crypto {
		pub = conn.keyPair.Public()
	}
	connectRequest := edge.NewConnectMsg(conn.Id(), *session.Token, pub, options)
	connectRequest.PutStringHeader(edge.ConnectionMarkerHeader, conn.marker)
	connectRequest.PutBoolHeader(edge.UseXgressToSdkHeader, options.SdkFlowControl)

	conn.TraceMsg("connect", connectRequest)
	replyMsg, err := connectRequest.WithContext(ctx).SendForReply(ch.GetControlSender())
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if replyMsg.ContentType == edge.ContentTypeStateClosed {
		// PIRATE-RAWR
		return nil, pkgerrors.Errorf("dial failed: %v", string(replyMsg.Body))
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		return nil, pkgerrors.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
	}

	conn.circuitId, _ = replyMsg.GetStringHeader(edge.CircuitIdHeader)
	logger = logger.WithField("circuitId", conn.circuitId)

	if stickinessToken, ok := replyMsg.Headers[edge.StickinessTokenHeader]; ok {
		if conn.customState == nil {
			conn.customState = map[int32][]byte{}
		}
		conn.customState[edge.StickinessTokenHeader] = stickinessToken
	}

	if err = conn.setupFlowControl(replyMsg, xgress.Initiator, envF, ch, mux); err != nil {
		return nil, err
	}

	if conn.crypto {
		// There is no race condition where we can receive the other side crypto header
		// because the processing of the crypto header takes place in Conn.Read which
		// can't happen until we return the conn to the user. So as long as we send
		// the header and set rxkey before we return, we should be safe
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

	logger.Debug("connected")

	return conn, nil
}

// ConnectV2 performs a sessionless dial via the ConnectV2 protocol. The router authorizes
// the dial locally via RDM, so no service session token is required. The circuit ID is
// received early via a route_circuit message before the StateConnected reply.
func (conn *edgeConn) ConnectV2(ctx context.Context, serviceId string, identifierType edge.ServiceIdentifierType,
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
		return nil, pkgerrors.Errorf("dial failed: %v", string(replyMsg.Body))
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		pd.DialFailed()
		return nil, pkgerrors.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
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

	if err = conn.setupFlowControl(replyMsg, xgress.Initiator, envF, routerConn.ch, routerConn.mux); err != nil {
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

func (conn *edgeConn) setupFlowControl(msg *channel.Message, originator xgress.Originator,
	envF func() xgress.Env, ch edge.SdkChannel, mux edge.ConnMux[any]) error {

	if useXg, _ := msg.GetBoolHeader(edge.UseXgressToSdkHeader); useXg {
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
		conn.dfltSender = msgCh.GetDefaultSender()
		conn.routerId = ch.GetChannel().Id()
		conn.channelLabel = ch.GetChannel().LogicalName()
		conn.isXgress = true
	} else {
		if defaultConnections := ch.GetChannel().GetUnderlayCountsByType()[edge.ChannelTypeDefault]; defaultConnections > 1 {
			return pkgerrors.New("edge connections must use sdk flow control when using multiple default connections")
		}
		// legacy mode: fields already set at construction time, nothing to change
	}

	return nil
}

type newConnHandler struct {
	conn                 *edgeHostConn
	edgeCh               *edgeConn
	message              *channel.Message
	ctrlSender           channel.Sender
	txHeader             []byte
	routerProvidedConnId bool
	circuitId            string
}

func (self *newConnHandler) dialFailed(err error) {
	token := string(self.message.Body)
	logger := pfxlog.Logger().WithField("connId", self.conn.Id()).WithField("token", token)

	newConnLogger := pfxlog.Logger().
		WithField("connId", self.edgeCh.Id()).
		WithField("parentConnId", self.conn.Id()).
		WithField("token", token)

	newConnLogger.WithError(err).Error("Failed to establish connection")
	reply := edge.NewDialFailedMsg(self.conn.Id(), err.Error())
	reply.ReplyTo(self.message)
	if err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(self.ctrlSender); err != nil {
		logger.WithError(err).Error("Failed to send reply to dial request")
	}
}

func (self *newConnHandler) dialSucceeded() (error, bool) {
	logger := pfxlog.Logger().WithField("connId", self.conn.Id()).WithField("circuitId", self.circuitId)

	newConnLogger := pfxlog.Logger().
		WithField("connId", self.edgeCh.Id()).
		WithField("marker", self.edgeCh.marker).
		WithField("parentConnId", self.conn.Id()).
		WithField("circuitId", self.circuitId)

	newConnLogger.Debug("new connection established")

	reply := edge.NewDialSuccessMsg(self.conn.Id(), self.edgeCh.Id())
	reply.ReplyTo(self.message)

	if !self.routerProvidedConnId {
		startMsg, err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendForReply(self.ctrlSender)
		if err != nil {
			logger.WithError(err).Error("failed to send reply to dial request")
			return err, false
		}

		if startMsg.ContentType != edge.ContentTypeStateConnected {
			logger.Errorf("failed to receive start after dial. got %v", startMsg)
			self.edgeCh.close(true)
			return pkgerrors.Errorf("failed to receive start after dial. got %v", startMsg), true
		}
	} else if err := reply.WithPriority(channel.Highest).WithTimeout(time.Second * 5).SendAndWaitForWire(self.ctrlSender); err != nil {
		logger.WithError(err).Error("failed to send reply to dial request")
		return err, false
	}

	if self.txHeader != nil {
		newConnLogger.Debug("sending crypto header")
		if _, err := self.edgeCh.DataSink().Write(self.txHeader); err != nil {
			newConnLogger.WithError(err).Error("failed to write crypto header")
			self.edgeCh.close(true)
			return err, true
		}
		newConnLogger.Debug("tx crypto established")
	}

	return nil, false
}
