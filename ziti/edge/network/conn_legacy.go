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

var unsupportedCrypto = pkgerrors.New("unsupported crypto")

var _ edge.Conn = &edgeConnLegacy{}
var _ edgeConnOps = &edgeConnLegacy{}

// edgeConnLegacy is an edge connection in "legacy" flow-control mode: data
// is carried as discrete ContentTypeData messages on the edge channel, with
// acks/backpressure handled at the channel layer. It has no xgress plumbing.
type edgeConnLegacy struct {
	edgeConnBase

	msgCh edge.MsgChannel
	mux   edge.ConnMux[any]
	readQ *noopSeq[*channel.Message]
}

// --- edgeConnOps implementation ---

func (conn *edgeConnLegacy) Id() uint32 {
	return conn.msgCh.Id()
}

func (conn *edgeConnLegacy) readSource() ([]byte, uint32, error) {
	for {
		msg, err := conn.readQ.GetNext()
		if err != nil {
			return nil, 0, err
		}

		flags, _ := msg.GetUint32Header(edge.FlagsHeader)

		switch msg.ContentType {
		case edge.ContentTypeStateClosed:
			conn.handleStateClosedInRead()
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

func (conn *edgeConnLegacy) initChunkReader() {
	conn.chunkReader = newEdgeChunkReader(conn.readSource, func() *logrus.Entry {
		return pfxlog.Logger().
			WithField("connId", conn.Id()).
			WithField("marker", conn.marker).
			WithField("circuitId", conn.circuitId)
	})
}

func (conn *edgeConnLegacy) DataSink() io.Writer {
	return &conn.msgCh
}

func (conn *edgeConnLegacy) CloseConn(notifyCtrl bool) {
	log := pfxlog.Logger().WithField("connId", int(conn.Id())).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)

	if notifyCtrl {
		msg := edge.NewStateClosedMsg(conn.Id(), "")
		if err := conn.msgCh.SendState(msg); err != nil {
			log.WithError(err).Error("failed to send close message")
		}
	}

	conn.mux.RemoveByConnId(conn.Id())
}

// --- Direct methods ---

func (conn *edgeConnLegacy) TraceMsg(source string, msg *channel.Message) {
	conn.msgCh.TraceMsg(source, msg)
}

func (conn *edgeConnLegacy) Peers() []string {
	return []string{"r/" + conn.msgCh.GetChannel().Id()}
}

func (conn *edgeConnLegacy) RemoteAddr() net.Addr {
	return &edge.Addr{MsgCh: conn.msgCh}
}

func (conn *edgeConnLegacy) CloseWrite() error {
	if conn.sentFIN.CompareAndSwap(false, true) {
		headers := channel.Headers{}
		headers.PutUint32Header(edge.FlagsHeader, edge.FIN)
		_, err := conn.msgCh.WriteTraced(nil, nil, headers)
		return err
	}
	return nil
}

func (conn *edgeConnLegacy) SetWriteDeadline(t time.Time) error {
	return conn.msgCh.SetWriteDeadline(t)
}

func (conn *edgeConnLegacy) SetReadDeadline(t time.Time) error {
	conn.readQ.SetReadDeadline(t)
	return nil
}

func (conn *edgeConnLegacy) handleStateClosedInRead() {
	pfxlog.Logger().WithField("connId", conn.Id()).
		WithField("marker", conn.marker).
		WithField("circuitId", conn.circuitId).
		Debug("received ConnState_CLOSED message, closing connection")
	conn.doClose(false, conn)
}

func (conn *edgeConnLegacy) HandleMuxClose() error {
	conn.doClose(false, conn)
	return nil
}

func (conn *edgeConnLegacy) HandleClose(channel.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.doClose(false, conn)
}

func (conn *edgeConnLegacy) queueMessage(msg *channel.Message) {
	if err := conn.readQ.PutSequenced(msg); err != nil {
		logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
			Error("error pushing edge message to sequencer")
	} else {
		logrus.WithFields(edge.GetLoggerFields(msg)).Debugf("received %v bytes (msg type: %v)", len(msg.Body), msg.ContentType)
	}
}

func (conn *edgeConnLegacy) GetCircuitDetail() *xgress.CircuitDetail {
	return &xgress.CircuitDetail{
		CircuitId: conn.circuitId,
		ConnId:    conn.Id(),
	}
}

// --- Standard conn methods ---

func (conn *edgeConnLegacy) Write(data []byte) (int, error) {
	return conn.doWrite(data, &conn.msgCh)
}

func (conn *edgeConnLegacy) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn")
	conn.doClose(true, conn)
	return nil
}

func (conn *edgeConnLegacy) close(notifyCtrl bool) {
	conn.doClose(notifyCtrl, conn)
}

func (conn *edgeConnLegacy) InspectSink() *inspect.VirtualConnDetail {
	return conn.edgeConnBase.InspectSink(conn.Id())
}

// Inspect returns a JSON snapshot of this legacy connection's state. connId is
// the primary identifier for legacy conns — it's what disambiguates conns on
// the edge channel.
func (conn *edgeConnLegacy) Inspect() string {
	state := conn.baseState()
	state["id"] = conn.Id()
	return marshalState(state)
}

// GetState returns a JSON dump of this connection's state. For legacy conns
// this matches Inspect exactly — there are no mode-specific fields.
func (conn *edgeConnLegacy) GetState() string {
	return conn.Inspect()
}

// HandleConnInspect replies to a ContentTypeConnInspectRequest with the JSON
// state from Inspect.
func (conn *edgeConnLegacy) HandleConnInspect(msg *channel.Message, ch edge.SdkChannel) {
	conn.edgeConnBase.HandleConnInspect(conn.Id(), conn.Inspect(), msg, ch)
}

// handleTraceRoute handles an incoming trace route request. The dialer's edge
// router invokes this when hops reaches this SDK-side terminator (via the
// router's msgMux connId routing). The response is keyed by connId and rides
// the edge channel directly.
func (conn *edgeConnLegacy) handleTraceRoute(msg *channel.Message, ch edge.SdkChannel) {
	hops, _ := msg.GetUint32Header(edge.TraceHopCountHeader)
	if hops > 0 {
		hops--
		msg.PutUint32Header(edge.TraceHopCountHeader, hops)
	}

	ts, _ := msg.GetUint64Header(edge.TimestampHeader)
	connId, _ := msg.GetUint32Header(edge.ConnIdHeader)
	resp := edge.NewTraceRouteResponseMsg(connId, hops, ts, "sdk/golang", "")

	sourceRequestId, _ := msg.GetUint32Header(edge.TraceSourceRequestIdHeader)
	resp.PutUint32Header(edge.TraceSourceRequestIdHeader, sourceRequestId)

	if msgUUID := msg.Headers[edge.UUIDHeader]; msgUUID != nil {
		resp.Headers[edge.UUIDHeader] = msgUUID
	}

	if err := ch.GetControlSender().Send(resp); err != nil {
		logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
			Error("failed to send trace route response")
	}
}

// HandleInspect replies to a ContentTypeInspectRequest. Legacy conns have no
// circuit-level inspect data to return, so the reply is an empty success.
func (conn *edgeConnLegacy) HandleInspect(msg *channel.Message, ch edge.SdkChannel) {
	sendInspectReply(conn.Id(), msg, ch, &inspect.SdkInspectResponse{
		Success: true,
		Values:  map[string]any{},
	})
}

func (conn *edgeConnLegacy) String() string {
	return fmt.Sprintf("zitiConn connId=%v svcId=%v sourceIdentity=%v", conn.Id(), conn.serviceName, conn.sourceIdentity)
}

func (conn *edgeConnLegacy) LocalAddr() net.Addr {
	return conn
}

func (conn *edgeConnLegacy) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConnLegacy) CompleteAcceptSuccess() error {
	return conn.edgeConnBase.CompleteAcceptSuccess(conn.Id(), conn)
}

// TraceRoute initiates a trace route from this legacy conn. Uses the
// connId-keyed edge protocol: ContentTypeTraceRoute / ContentTypeTraceRouteResponse.
func (conn *edgeConnLegacy) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	msg := edge.NewTraceRouteMsg(conn.Id(), hops, uint64(info.NowInMilliseconds()))
	resp, err := msg.WithTimeout(timeout).SendForReply(conn.msgCh.GetDefaultSender())
	if err != nil {
		return nil, err
	}
	if resp.ContentType != edge.ContentTypeTraceRouteResponse {
		return nil, pkgerrors.Errorf("unexpected response: %v", resp.ContentType)
	}
	respHops, _ := resp.GetUint32Header(edge.TraceHopCountHeader)
	ts, _ := resp.GetUint64Header(edge.TimestampHeader)
	elapsed := time.Duration(0)
	if ts > 0 {
		elapsed = time.Duration(info.NowInMilliseconds()-int64(ts)) * time.Millisecond
	}
	hopType, _ := resp.GetStringHeader(edge.TraceHopTypeHeader)
	hopId, _ := resp.GetStringHeader(edge.TraceHopIdHeader)
	hopErr, _ := resp.GetStringHeader(edge.TraceError)

	return &edge.TraceRouteResult{
		Hops:    respHops,
		Time:    elapsed,
		HopType: hopType,
		HopId:   hopId,
		Error:   hopErr,
	}, nil
}

func (conn *edgeConnLegacy) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	if err := conn.doEstablishClientCrypto(keypair, peerKey, method, &conn.msgCh); err != nil {
		return err
	}

	pfxlog.Logger().
		WithField("connId", conn.Id()).
		WithField("marker", conn.marker).
		Debug("crypto established")

	return nil
}

func (conn *edgeConnLegacy) AcceptMessage(msg *channel.Message, ch edge.SdkChannel) {
	conn.TraceMsg("AcceptMessage", msg)

	if msg.ContentType == edge.ContentTypeConnInspectRequest {
		go conn.HandleConnInspect(msg, ch)
		return
	}

	switch msg.ContentType {
	case edge.ContentTypeStateClosed:
		if conn.IsClosed() {
			return
		}
		conn.sentFIN.Store(true) // if we're not closing until all reads are done, at least prevent more writes

	case edge.ContentTypeInspectRequest:
		go conn.HandleInspect(msg, ch)
		return

	case edge.ContentTypeTraceRoute:
		go conn.handleTraceRoute(msg, ch)
		return
	}

	conn.queueMessage(msg)
}

// acceptableConn is the interface that newConnHandler holds to defer a dial
// accept. Both edgeConnLegacy and edgeConnXgress implement it.
type acceptableConn interface {
	Id() uint32
	Marker() string
	DataSink() io.Writer
	close(notifyCtrl bool)
}

type newConnHandler struct {
	conn                 *edgeHostConn
	edgeCh               acceptableConn
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
		WithField("marker", self.edgeCh.Marker()).
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
