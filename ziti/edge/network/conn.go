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
	"encoding/json"
	"fmt"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/xgress"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/info"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream"
	"github.com/openziti/secretstream/kx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var unsupportedCrypto = errors.New("unsupported crypto")

var _ edge.Conn = &edgeConn{}

type edgeConn struct {
	edge.MsgChannel
	readQ                 *noopSeq[*channel.Message]
	inBuffer              [][]byte
	msgMux                edge.MsgMux
	flags                 uint32
	closed                atomic.Bool
	closeNotify           chan struct{}
	readFIN               atomic.Bool
	sentFIN               atomic.Bool
	serviceName           string
	sourceIdentity        string
	acceptCompleteHandler *newConnHandler
	marker                string
	circuitId             string
	customState           map[int32][]byte

	crypto   bool
	keyPair  *kx.KeyPair
	rxKey    []byte
	receiver secretstream.Decryptor
	sender   secretstream.Encryptor
	appData  []byte
	sync.Mutex

	dataSink  io.Writer
	xgCircuit *XgAdapter
}

func (conn *edgeConn) Write(data []byte) (int, error) {
	if conn.sentFIN.Load() {
		if conn.IsClosed() {
			return 0, errors.New("connection closed")
		}
		return 0, errors.New("calling Write() after CloseWrite()")
	}

	if conn.sender != nil {
		conn.Lock()
		defer conn.Unlock()

		cipherData, err := conn.sender.Push(data, secretstream.TagMessage)
		if err != nil {
			return 0, err
		}

		_, err = conn.dataSink.Write(cipherData)
		return len(data), err
	} else {
		copyBuf := make([]byte, len(data))
		copy(copyBuf, data)

		return conn.dataSink.Write(copyBuf)
	}
}

func (conn *edgeConn) CloseWrite() error {
	if conn.sentFIN.CompareAndSwap(false, true) {
		headers := channel.Headers{}
		headers.PutUint32Header(edge.FlagsHeader, edge.FIN)
		_, err := conn.WriteTraced(nil, nil, headers)

		if conn.xgCircuit != nil {
			conn.xgCircuit.xg.CloseRxTimeout()
		}

		return err
	}

	return nil
}

func (conn *edgeConn) Inspect() string {
	state := conn.getBaseState()
	jsonOutput, err := json.Marshal(state)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("unable to marshal inspect result")
	}
	return string(jsonOutput)
}

func (conn *edgeConn) getBaseState() map[string]any {
	result := map[string]interface{}{}
	result["id"] = conn.Id()
	result["serviceName"] = conn.serviceName
	result["closed"] = conn.closed.Load()
	result["encryptionRequired"] = conn.crypto
	result["encrypted"] = conn.rxKey != nil || conn.receiver != nil
	result["readFIN"] = conn.readFIN.Load()
	result["sentFIN"] = conn.sentFIN.Load()
	result["marker"] = conn.marker
	result["circuitId"] = conn.circuitId
	return result
}

func (conn *edgeConn) GetState() string {
	state := conn.getBaseState()
	if conn.xgCircuit != nil && conn.xgCircuit.xg != nil {
		state["xg"] = conn.xgCircuit.xg.GetInspectDetail(true)
	}
	jsonOutput, err := json.Marshal(state)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("unable to marshal inspect result")
	}
	return string(jsonOutput)
}

func (conn *edgeConn) Accept(msg *channel.Message) {
	conn.TraceMsg("Accept", msg)

	if msg.ContentType == edge.ContentTypeConnInspectRequest {
		resp := edge.NewConnInspectResponse(0, edge.ConnTypeDial, conn.Inspect())
		if err := resp.ReplyTo(msg).Send(conn.GetControlSender()); err != nil {
			logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
				Error("failed to send inspect response")
		}
		return
	}

	switch msg.ContentType {
	case edge.ContentTypeXgPayload:
		conn.HandleXgPayload(msg)
		return

	case edge.ContentTypeXgAcknowledgement:
		conn.HandleXgAcknowledgement(msg)
		return

	case edge.ContentTypeStateClosed:
		if conn.IsClosed() {
			return
		}
		// routing is not accepting more data, so we need to close the send buffer
		if conn.xgCircuit != nil {
			conn.xgCircuit.xg.CloseSendBuffer()
		}
		conn.sentFIN.Store(true) // if we're not closing until all reads are done, at least prevent more writes

	case edge.ContentTypeInspectRequest:
		conn.HandleInspect(msg)
		return

	case edge.ContentTypeTraceRoute:
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

		if err := conn.GetControlSender().Send(resp); err != nil {
			logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
				Error("failed to send trace route response")
		}
		return
	}

	if err := conn.readQ.PutSequenced(msg); err != nil {
		logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
			Error("error pushing edge message to sequencer")
	} else {
		logrus.WithFields(edge.GetLoggerFields(msg)).Debugf("received %v bytes (msg type: %v)", len(msg.Body), msg.ContentType)
	}
}

func (conn *edgeConn) HandleXgPayload(msg *channel.Message) {
	adapter := conn.xgCircuit

	if adapter == nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).Error("can't accept payload, xgress adapter not present")
		return
	}

	payload, err := xgress.UnmarshallPayload(msg)
	if err != nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error unmarshalling payload")
		adapter.xg.Close()
		return
	}

	if err = adapter.xg.SendPayload(payload, 0, 0); err != nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error accepting payload")
		adapter.xg.Close()
	}
}

func (conn *edgeConn) HandleXgAcknowledgement(msg *channel.Message) {
	adapter := conn.xgCircuit
	if adapter == nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).Error("can't accept ack, xgress adapter not present")
		return
	}

	ack, err := xgress.UnmarshallAcknowledgement(msg)
	if err != nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error unmarshalling acknowledgement")
		adapter.xg.Close()
		return
	}

	if err = adapter.xg.SendAcknowledgement(ack); err != nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error accepting acknowledgement")
		adapter.xg.Close()
	}
	// adapter.env.GetAckIngester().Ingest(msg, adapter.xg)
}

func (conn *edgeConn) HandleInspect(msg *channel.Message) {
	resp := &inspect.SdkInspectResponse{
		Success: true,
		Values:  make(map[string]any),
	}
	requestedValues, _, err := msg.GetStringSliceHeader(edge.InspectRequestValuesHeader)
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
		resp.Success = false
		conn.returnInspectResponse(msg, resp)
		return
	}

	for _, requested := range requestedValues {
		lc := strings.ToLower(requested)
		if strings.HasPrefix(lc, "circuit:") {
			circuitId := requested[len("circuit:"):]
			if conn.xgCircuit != nil && conn.circuitId == circuitId {
				detail := conn.xgCircuit.xg.GetInspectDetail(false)
				resp.Values[requested] = detail
			}
		} else if strings.HasPrefix(lc, "circuitandstacks:") {
			circuitId := requested[len("circuitAndStacks:"):]
			if conn.xgCircuit != nil && conn.circuitId == circuitId {
				detail := conn.xgCircuit.xg.GetInspectDetail(true)
				resp.Values[requested] = detail
			}
		}
	}

	conn.returnInspectResponse(msg, resp)
}

func (conn *edgeConn) GetCircuitDetail() *xgress.CircuitDetail {
	detail := &xgress.CircuitDetail{
		CircuitId: conn.circuitId,
		ConnId:    conn.Id(),
	}

	if conn.xgCircuit != nil {
		detail.IsXgress = true
		detail.Originator = conn.xgCircuit.xg.Originator().String()
		detail.Address = string(conn.xgCircuit.xg.Address())
		detail.CtrlId = conn.xgCircuit.xg.CtrlId()
	}

	return detail
}

func (conn *edgeConn) returnInspectResponse(msg *channel.Message, resp *inspect.SdkInspectResponse) {
	reply, err := edge.NewInspectResponse(conn.Id(), resp)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("failed to create inspect response")
		return
	}
	reply.ReplyTo(msg)

	if err = reply.WithTimeout(5 * time.Second).Send(conn.GetControlSender()); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send inspect response")
	}
}

func (conn *edgeConn) IsClosed() bool {
	return conn.closed.Load()
}

func (conn *edgeConn) Network() string {
	return conn.serviceName
}

func (conn *edgeConn) String() string {
	return fmt.Sprintf("zitiConn connId=%v svcId=%v sourceIdentity=%v", conn.Id(), conn.serviceName, conn.sourceIdentity)
}

func (conn *edgeConn) LocalAddr() net.Addr {
	return conn
}

func (conn *edgeConn) RemoteAddr() net.Addr {
	return &edge.Addr{MsgCh: conn.MsgChannel}
}

func (conn *edgeConn) SourceIdentifier() string {
	return conn.sourceIdentity
}

func (conn *edgeConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConn) SetWriteDeadline(t time.Time) error {
	if conn.xgCircuit != nil {
		return conn.xgCircuit.writeAdapter.SetWriteDeadline(t)
	}
	return conn.MsgChannel.SetWriteDeadline(t)
}

func (conn *edgeConn) SetReadDeadline(t time.Time) error {
	conn.readQ.SetReadDeadline(t)
	return nil
}

func (conn *edgeConn) HandleMuxClose() error {
	conn.close(true)

	// If the channel is closed, stop the send buffer as we can't rtx anything anyway
	if xgCircuit := conn.xgCircuit; xgCircuit != nil {
		xgCircuit.xg.Close()
	}
	return nil
}

func (conn *edgeConn) GetCircuitId() string {
	return conn.circuitId
}

func (conn *edgeConn) GetStickinessToken() []byte {
	return conn.customState[edge.StickinessTokenHeader]
}

func (conn *edgeConn) HandleClose(channel.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.close(true)
	if conn.xgCircuit != nil {
		conn.xgCircuit.xg.CloseSendBuffer()
	}
}

func (conn *edgeConn) Connect(session *rest_model.SessionDetail, options *edge.DialOptions, envF func() xgress.Env) (edge.Conn, error) {
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
	replyMsg, err := connectRequest.WithTimeout(options.ConnectTimeout).SendForReply(conn.GetControlSender())
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if replyMsg.ContentType == edge.ContentTypeStateClosed {
		return nil, errors.Errorf("dial failed: %v", string(replyMsg.Body))
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		return nil, errors.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
	}

	conn.circuitId, _ = replyMsg.GetStringHeader(edge.CircuitIdHeader)
	logger = logger.WithField("circuitId", conn.circuitId)

	if stickinessToken, ok := replyMsg.Headers[edge.StickinessTokenHeader]; ok {
		if conn.customState == nil {
			conn.customState = map[int32][]byte{}
		}
		conn.customState[edge.StickinessTokenHeader] = stickinessToken
	}

	if err = conn.setupFlowControl(replyMsg, xgress.Initiator, envF); err != nil {
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

func (conn *edgeConn) setupFlowControl(msg *channel.Message, originator xgress.Originator, envF func() xgress.Env) error {
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

		xgAdapter := &XgAdapter{
			conn:  conn,
			readC: make(chan []byte),
			env:   envF(),
		}
		conn.xgCircuit = xgAdapter
		xg := xgress.NewXgress(conn.circuitId, ctrlId, xgress.Address(addr), xgAdapter, originator, xgress.DefaultOptions(), nil)
		xgAdapter.xg = xg
		xgAdapter.writeAdapter = xg.NewWriteAdapter()
		xgAdapter.xg.AddCloseHandler(xgAdapter)
		conn.dataSink = xgAdapter.writeAdapter

		xg.SetDataPlaneAdapter(xgAdapter)
		xg.Start()
	} else {
		if defaultConnections := conn.GetChannel().GetUnderlayCountsByType()[edge.ChannelTypeDefault]; defaultConnections > 1 {
			return errors.New("edge connections must use sdk flow control when using multiple default connections")
		}
		conn.dataSink = &conn.MsgChannel
	}

	return nil
}

func (conn *edgeConn) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	var err error
	var rx, tx []byte

	if method != edge.CryptoMethodLibsodium {
		return unsupportedCrypto
	}

	if rx, tx, err = keypair.ClientSessionKeys(peerKey); err != nil {
		return errors.Wrap(err, "failed key exchange")
	}

	var txHeader []byte
	if conn.sender, txHeader, err = secretstream.NewEncryptor(tx); err != nil {
		return errors.Wrap(err, "failed to establish crypto stream")
	}

	conn.rxKey = rx

	if _, err = conn.dataSink.Write(txHeader); err != nil {
		return errors.Wrap(err, "failed to write crypto header")
	}

	pfxlog.Logger().
		WithField("connId", conn.Id()).
		WithField("marker", conn.marker).
		Debug("crypto established")
	return nil
}

func (conn *edgeConn) establishServerCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) ([]byte, error) {
	var err error
	var rx, tx []byte

	if method != edge.CryptoMethodLibsodium {
		return nil, unsupportedCrypto
	}
	if rx, tx, err = keypair.ServerSessionKeys(peerKey); err != nil {
		return nil, errors.Wrap(err, "failed key exchange")
	}

	var txHeader []byte
	if conn.sender, txHeader, err = secretstream.NewEncryptor(tx); err != nil {
		return nil, errors.Wrap(err, "failed to establish crypto stream")
	}

	conn.rxKey = rx

	return txHeader, nil
}

func (conn *edgeConn) Read(p []byte) (int, error) {
	log := pfxlog.Logger().WithField("connId", conn.Id()).
		WithField("marker", conn.marker).
		WithField("circuitId", conn.circuitId)

	if conn.closed.Load() {
		log.Trace("edgeConn closed, returning EOF")
		return 0, io.EOF
	}

	log.Tracef("read buffer = %d bytes", len(p))
	if len(conn.inBuffer) > 0 {
		first := conn.inBuffer[0]
		log.Tracef("found %d buffered bytes", len(first))
		n := copy(p, first)
		first = first[n:]
		if len(first) == 0 {
			conn.inBuffer = conn.inBuffer[1:]
		} else {
			conn.inBuffer[0] = first
		}
		return n, nil
	}

	for {
		if conn.readFIN.Load() {
			log.Tracef("readFIN true, returning EOF")
			return 0, io.EOF
		}

		msg, err := conn.readQ.GetNext()
		if errors.Is(err, ErrClosed) {
			log.Debug("sequencer closed, marking readFIN")
			conn.readFIN.Store(true)
			return 0, io.EOF
		} else if err != nil {
			log.WithError(err).Debug("unexpected sequencer err")
			return 0, err
		}

		flags, _ := msg.GetUint32Header(edge.FlagsHeader)
		if flags&edge.FIN != 0 {
			log.Trace("got fin msg, marking readFIN true")
			conn.readFIN.Store(true)
		}
		conn.flags = conn.flags | (flags & (edge.STREAM | edge.MULTIPART))

		switch msg.ContentType {

		case edge.ContentTypeStateClosed:
			if conn.xgCircuit != nil {
				conn.readFIN.Store(true)
				if conn.sentFIN.Load() {
					log.Debug("received ConnState_CLOSED message, fin sent, closing connection")
					conn.close(true)
				} else {
					log.Debug("received ConnState_CLOSED message, fin not yet sent")
				}
			} else {
				log.Debug("received ConnState_CLOSED message, closing connection")
				conn.close(true)
			}
			continue

		case edge.ContentTypeData:
			d := msg.Body
			log.Tracef("got buffer from sequencer %d bytes", len(d))
			if len(d) == 0 && conn.readFIN.Load() {
				return 0, io.EOF
			}

			multipart := (flags & edge.MULTIPART_MSG) != 0

			// first data message should contain crypto header
			if conn.rxKey != nil {
				if len(d) != secretstream.StreamHeaderBytes {
					return 0, errors.Errorf("failed to receive crypto header bytes: read[%d]", len(d))
				}
				conn.receiver, err = secretstream.NewDecryptor(conn.rxKey, d)
				if err != nil {
					return 0, errors.Wrap(err, "failed to init decryptor")
				}
				conn.rxKey = nil
				continue
			}

			if conn.receiver != nil {
				d, _, err = conn.receiver.Pull(d)
				if err != nil {
					log.WithFields(edge.GetLoggerFields(msg)).Errorf("crypto failed on msg of size=%v, headers=%+v err=(%v)", len(msg.Body), msg.Headers, err)
					return 0, err
				}
			}
			n := 0
			if multipart && len(d) > 0 {
				var parts [][]byte
				for len(d) > 0 {
					l := binary.LittleEndian.Uint16(d[0:2])
					d = d[2:]
					part := d[0:l]
					d = d[l:]
					parts = append(parts, part)
				}
				n = copy(p, parts[0])
				parts[0] = parts[0][n:]
				if len(parts[0]) == 0 {
					parts = parts[1:]
				}
				conn.inBuffer = append(conn.inBuffer, parts...)
			} else {
				n = copy(p, d)
				d = d[n:]
				if len(d) > 0 {
					conn.inBuffer = append(conn.inBuffer, d)
				}
			}

			log.Tracef("%d chunks in incoming buffer", len(conn.inBuffer))
			log.Debugf("read %v bytes", n)
			return n, nil

		default:
			log.WithField("type", msg.ContentType).Error("unexpected message")
		}
	}
}

func (conn *edgeConn) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn")
	conn.close(false)
	return nil
}

func (conn *edgeConn) close(closedByRemote bool) {
	// everything in here should be safe to execute concurrently from outside the muxer loop,
	// except the remove from mux call
	if !conn.closed.CompareAndSwap(false, true) {
		return
	}

	close(conn.closeNotify)

	conn.readFIN.Store(true)
	conn.sentFIN.Store(true)

	log := pfxlog.Logger().WithField("connId", int(conn.Id())).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)

	log.Debug("close: begin")
	defer log.Debug("close: end")

	if conn.xgCircuit == nil {
		if !closedByRemote {
			msg := edge.NewStateClosedMsg(conn.Id(), "")
			if err := conn.SendState(msg); err != nil {
				log.WithError(err).Error("failed to send close message")
			}
		}

		conn.msgMux.RemoveMsgSink(conn) // if we switch back to ChMsgMux will need to be done async again, otherwise we may deadlock
	} else {
		// cancel any pending writes
		_ = conn.xgCircuit.writeAdapter.SetWriteDeadline(time.Now())

		// if we're using xgress, wait to remove the connection from the mux until the xgress closes, otherwise it becomes unroutable.
		conn.xgCircuit.xg.PeerClosed()
	}
}

func (conn *edgeConn) GetAppData() []byte {
	return conn.appData
}

func (conn *edgeConn) CompleteAcceptSuccess() error {
	if conn.acceptCompleteHandler != nil {
		result := conn.acceptCompleteHandler.dialSucceeded()
		conn.acceptCompleteHandler = nil
		return result
	}
	return nil
}

func (conn *edgeConn) CompleteAcceptFailed(err error) {
	if conn.acceptCompleteHandler != nil {
		conn.acceptCompleteHandler.dialFailed(err)
		conn.acceptCompleteHandler = nil
	}
}

func (conn *edgeConn) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	msg := edge.NewTraceRouteMsg(conn.Id(), hops, uint64(info.NowInMilliseconds()))
	resp, err := msg.WithTimeout(timeout).SendForReply(conn.GetDefaultSender())
	if err != nil {
		return nil, err
	}
	if resp.ContentType != edge.ContentTypeTraceRouteResponse {
		return nil, errors.Errorf("unexpected response: %v", resp.ContentType)
	}
	hops, _ = resp.GetUint32Header(edge.TraceHopCountHeader)
	ts, _ := resp.GetUint64Header(edge.TimestampHeader)
	elapsed := time.Duration(0)
	if ts > 0 {
		elapsed = time.Duration(info.NowInMilliseconds()-int64(ts)) * time.Millisecond
	}
	hopType, _ := resp.GetStringHeader(edge.TraceHopTypeHeader)
	hopId, _ := resp.GetStringHeader(edge.TraceHopIdHeader)
	hopErr, _ := resp.GetStringHeader(edge.TraceError)

	result := &edge.TraceRouteResult{
		Hops:    hops,
		Time:    elapsed,
		HopType: hopType,
		HopId:   hopId,
		Error:   hopErr,
	}
	return result, nil
}

type newConnHandler struct {
	conn                 *edgeHostConn
	edgeCh               *edgeConn
	message              *channel.Message
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
	if err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(self.conn.GetControlSender()); err != nil {
		logger.WithError(err).Error("Failed to send reply to dial request")
	}
}

func (self *newConnHandler) dialSucceeded() error {
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
		startMsg, err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendForReply(self.conn.GetControlSender())
		if err != nil {
			logger.WithError(err).Error("failed to send reply to dial request")
			return err
		}

		if startMsg.ContentType != edge.ContentTypeStateConnected {
			logger.Errorf("failed to receive start after dial. got %v", startMsg)
			return errors.Errorf("failed to receive start after dial. got %v", startMsg)
		}
	} else if err := reply.WithPriority(channel.Highest).WithTimeout(time.Second * 5).SendAndWaitForWire(self.conn.GetControlSender()); err != nil {
		logger.WithError(err).Error("failed to send reply to dial request")
		return err
	}

	if self.txHeader != nil {
		newConnLogger.Debug("sending crypto header")
		if _, err := self.edgeCh.dataSink.Write(self.txHeader); err != nil {
			newConnLogger.WithError(err).Error("failed to write crypto header")
			return err
		}
		newConnLogger.Debug("tx crypto established")
	}
	return nil
}

// make a random 8 byte string
func newMarker() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
