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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/foundation/v2/info"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream"
	"github.com/openziti/secretstream/kx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// edgeConnOps is the minimal interface that edgeConnBase helpers need from the concrete connection type.
type edgeConnOps interface {
	Id() uint32
	DataSink() io.Writer
	CloseConn(*edgeConnBase, bool)
	GetDelegateState() map[string]any
	HandleInspectConn(*edgeConnBase, []string, *inspect.SdkInspectResponse)
	SendTraceRoute(uint32, uint32, time.Duration) (*channel.Message, error)
}

// RouterSender provides access to the router channel for sending protocol messages.
// This is the interface that becomes pluggable for P2P multi-path.
type RouterSender interface {
	SendPayload(msg *channel.Message, ctx context.Context) error
	TrySendPayload(msg *channel.Message) (bool, error)
	SendAcknowledgement(msg *channel.Message) error
	SendControlMessage(msg *channel.Message) error
	IsClosed() bool
}

type routerSenderImpl struct {
	ch edge.MsgChannel
}

func newRouterSender(ch edge.MsgChannel) *routerSenderImpl {
	return &routerSenderImpl{ch: ch}
}

func (s *routerSenderImpl) SendPayload(msg *channel.Message, ctx context.Context) error {
	return msg.WithContext(ctx).SendAndWaitForWire(s.ch.GetDefaultSender())
}

func (s *routerSenderImpl) TrySendPayload(msg *channel.Message) (bool, error) {
	return s.ch.GetDefaultSender().TrySend(msg)
}

func (s *routerSenderImpl) SendAcknowledgement(msg *channel.Message) error {
	return s.ch.GetDefaultSender().Send(msg)
}

func (s *routerSenderImpl) SendControlMessage(msg *channel.Message) error {
	return s.ch.GetDefaultSender().Send(msg)
}

func (s *routerSenderImpl) IsClosed() bool {
	return s.ch.GetChannel().IsClosed()
}

// edgeConnBase contains the shared fields and delegate-free methods for edge connections.
// Both edgeConnLegacy and edgeConnXgress embed this type.
type edgeConnBase struct {
	closed                atomic.Bool
	closeNotify           chan struct{}
	sentFIN               atomic.Bool
	serviceName           string
	sourceIdentity        string
	acceptCompleteHandler *newConnHandler
	marker                string
	circuitId             string
	customState           map[int32][]byte
	crypto                bool
	keyPair               *kx.KeyPair
	sender                secretstream.Encryptor
	chunkReader           *edgeChunkReader
	appData               []byte
	sync.Mutex
	data atomic.Value
}

// GetData retrieves arbitrary connection-specific context data associated with this connection.
func (base *edgeConnBase) GetData() any {
	return base.data.Load()
}

// SetData stores arbitrary connection-specific context data for this connection.
func (base *edgeConnBase) SetData(data any) {
	base.data.Store(data)
}

// IsClosed returns true if this connection has been closed.
func (base *edgeConnBase) IsClosed() bool {
	return base.closed.Load()
}

// Network returns the service name for this connection.
func (base *edgeConnBase) Network() string {
	return base.serviceName
}

// SourceIdentifier returns the source identity of this connection.
func (base *edgeConnBase) SourceIdentifier() string {
	return base.sourceIdentity
}

// GetCircuitId returns the circuit ID for this connection.
func (base *edgeConnBase) GetCircuitId() string {
	return base.circuitId
}

// GetStickinessToken returns the stickiness token from the custom state.
func (base *edgeConnBase) GetStickinessToken() []byte {
	return base.customState[edge.StickinessTokenHeader]
}

// GetDialerIdentityId returns the dialer identity ID from the custom state.
func (base *edgeConnBase) GetDialerIdentityId() string {
	return string(base.customState[edge.DialerIdentityId])
}

// GetDialerIdentityName returns the dialer identity name from the custom state.
func (base *edgeConnBase) GetDialerIdentityName() string {
	return string(base.customState[edge.DialerIdentityName])
}

// GetAppData returns the application data sent during connection establishment.
func (base *edgeConnBase) GetAppData() []byte {
	return base.appData
}

// Marker returns the random tracing marker for this connection.
func (base *edgeConnBase) Marker() string {
	return base.marker
}

// setAcceptCompleteHandler installs the deferred-accept handler used for
// manualStart listeners.
func (base *edgeConnBase) setAcceptCompleteHandler(h *newConnHandler) {
	base.acceptCompleteHandler = h
}

func (base *edgeConnBase) getBaseState() map[string]any {
	result := map[string]interface{}{}
	result["serviceName"] = base.serviceName
	result["closed"] = base.closed.Load()
	result["encryptionRequired"] = base.crypto
	result["encrypted"] = base.chunkReader.IsEncrypted()
	result["readFIN"] = base.chunkReader.ReadFIN()
	result["sentFIN"] = base.sentFIN.Load()
	result["marker"] = base.marker
	result["circuitId"] = base.circuitId
	return result
}

// Inspect returns a JSON string of this connection's base state.
func (base *edgeConnBase) Inspect(connId uint32) string {
	state := base.getBaseState()
	state["id"] = connId
	jsonOutput, err := json.Marshal(state)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("unable to marshal inspect result")
	}
	return string(jsonOutput)
}

// InspectSink returns a VirtualConnDetail for this connection.
func (base *edgeConnBase) InspectSink(connId uint32) *inspect.VirtualConnDetail {
	return &inspect.VirtualConnDetail{
		ConnId:      connId,
		SinkType:    "dial",
		ServiceName: base.serviceName,
		Closed:      base.closed.Load(),
		CircuitId:   base.circuitId,
	}
}

// CompleteAcceptSuccess completes a manual-start accept handshake successfully.
func (base *edgeConnBase) CompleteAcceptSuccess(connId uint32, ops edgeConnOps) error {
	if base.acceptCompleteHandler != nil {
		err, cleanupHandled := base.acceptCompleteHandler.dialSucceeded()

		if err != nil && !cleanupHandled {
			logger := pfxlog.Logger().
				WithField("connId", connId).
				WithField("circuitId", base.circuitId)

			base.doClose(false, ops)

			reply := edge.NewDialFailedMsg(connId, err.Error())
			reply.ReplyTo(base.acceptCompleteHandler.message)
			if sendErr := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(base.acceptCompleteHandler.ctrlSender); sendErr != nil {
				logger.WithError(sendErr).Error("failed to send reply to dial request")
			}
		}

		base.acceptCompleteHandler = nil

		return err
	}
	return nil
}

// CompleteAcceptFailed completes a manual-start accept handshake with a failure.
func (base *edgeConnBase) CompleteAcceptFailed(err error) {
	if base.acceptCompleteHandler != nil {
		base.acceptCompleteHandler.dialFailed(err)
		base.acceptCompleteHandler = nil
	}
}

// establishServerCrypto sets up server-side encryption keys and returns the tx header.
func (base *edgeConnBase) establishServerCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) ([]byte, error) {
	var err error
	var rx, tx []byte

	if method != edge.CryptoMethodLibsodium {
		return nil, unsupportedCrypto
	}
	if rx, tx, err = keypair.ServerSessionKeys(peerKey); err != nil {
		return nil, errors.Wrap(err, "failed key exchange")
	}

	var txHeader []byte
	if base.sender, txHeader, err = secretstream.NewEncryptor(tx); err != nil {
		return nil, errors.Wrap(err, "failed to establish crypto stream")
	}

	base.chunkReader.SetRxKey(rx)

	return txHeader, nil
}

// doRead performs the Read logic by delegating to the chunk reader, after
// a fast-path check for closed connections. The reader handles buffering,
// decryption, and multipart splitting.
func (base *edgeConnBase) doRead(p []byte, _ edgeConnOps) (int, error) {
	if base.closed.Load() {
		return 0, io.EOF
	}
	return base.chunkReader.Read(p)
}

// doWrite performs the Write logic, delegating mode-specific operations to the given edgeConnOps.
func (base *edgeConnBase) doWrite(data []byte, ops edgeConnOps) (int, error) {
	if base.sentFIN.Load() {
		if base.IsClosed() {
			return 0, errors.New("connection closed")
		}
		return 0, errors.New("connection closed for writes")
	}

	dataSink := ops.DataSink()
	if base.sender != nil {
		base.Lock()
		defer base.Unlock()

		cipherData, err := base.sender.Push(data, secretstream.TagMessage)
		if err != nil {
			return 0, err
		}

		_, err = dataSink.Write(cipherData)
		return len(data), err
	}

	copyBuf := make([]byte, len(data))
	copy(copyBuf, data)
	return dataSink.Write(copyBuf)
}

// doClose performs the close logic, delegating mode-specific operations to the given edgeConnOps.
func (base *edgeConnBase) doClose(notifyCtrl bool, ops edgeConnOps) {
	// everything in here should be safe to execute concurrently from outside the muxer loop,
	// except the remove from mux call
	if !base.closed.CompareAndSwap(false, true) {
		return
	}

	close(base.closeNotify)

	base.chunkReader.MarkFIN()
	base.sentFIN.Store(true)

	log := pfxlog.Logger().WithField("connId", int(ops.Id())).WithField("marker", base.marker).WithField("circuitId", base.circuitId)

	log.Debug("close: begin")
	defer log.Debug("close: end")

	ops.CloseConn(base, notifyCtrl)
}

// doEstablishClientCrypto sets up client-side encryption using the given ops' data sink.
func (base *edgeConnBase) doEstablishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod, ops edgeConnOps) error {
	var err error
	var rx, tx []byte

	if method != edge.CryptoMethodLibsodium {
		return unsupportedCrypto
	}

	if rx, tx, err = keypair.ClientSessionKeys(peerKey); err != nil {
		return errors.Wrap(err, "failed key exchange")
	}

	var txHeader []byte
	if base.sender, txHeader, err = secretstream.NewEncryptor(tx); err != nil {
		return errors.Wrap(err, "failed to establish crypto stream")
	}

	base.chunkReader.SetRxKey(rx)

	if _, err = ops.DataSink().Write(txHeader); err != nil {
		return errors.Wrap(err, "failed to write crypto header")
	}

	pfxlog.Logger().
		WithField("connId", ops.Id()).
		WithField("marker", base.marker).
		Debug("crypto established")
	return nil
}

// doGetState returns the combined base + ops state as a JSON string.
func (base *edgeConnBase) doGetState(connId uint32, ops edgeConnOps) string {
	state := base.getBaseState()
	state["id"] = connId
	if delegateState := ops.GetDelegateState(); delegateState != nil {
		for k, v := range delegateState {
			state[k] = v
		}
	}
	jsonOutput, err := json.Marshal(state)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("unable to marshal inspect result")
	}
	return string(jsonOutput)
}

// doHandleConnInspect handles a conn inspect request message.
func (base *edgeConnBase) doHandleConnInspect(connId uint32, msg *channel.Message, ch edge.SdkChannel) {
	resp := edge.NewConnInspectResponse(connId, edge.ConnTypeDial, base.Inspect(connId))
	if err := resp.ReplyTo(msg).Send(ch.GetControlSender()); err != nil {
		logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
			Error("failed to send inspect response")
	}
}

// doHandleTraceRoute handles a trace route request message.
func (base *edgeConnBase) doHandleTraceRoute(msg *channel.Message, ch edge.SdkChannel) {
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

// doHandleInspect handles an inspect request message.
func (base *edgeConnBase) doHandleInspect(connId uint32, ops edgeConnOps, msg *channel.Message, ch edge.SdkChannel) {
	resp := &inspect.SdkInspectResponse{
		Success: true,
		Values:  make(map[string]any),
	}
	requestedValues, _, err := msg.GetStringSliceHeader(edge.InspectRequestValuesHeader)
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
		resp.Success = false
		base.doReturnInspectResponse(connId, msg, ch, resp)
		return
	}

	ops.HandleInspectConn(base, requestedValues, resp)

	base.doReturnInspectResponse(connId, msg, ch, resp)
}

// doReturnInspectResponse sends an inspect response message.
func (base *edgeConnBase) doReturnInspectResponse(connId uint32, msg *channel.Message, ch edge.SdkChannel, resp *inspect.SdkInspectResponse) {
	reply, err := edge.NewInspectResponse(connId, resp)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("failed to create inspect response")
		return
	}
	reply.ReplyTo(msg)

	if err = reply.WithTimeout(5 * time.Second).Send(ch.GetControlSender()); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send inspect response")
	}
}

// doTraceRoute sends a trace route request and returns the result.
func (base *edgeConnBase) doTraceRoute(ops edgeConnOps, hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	connId := ops.Id()
	resp, err := ops.SendTraceRoute(connId, hops, timeout)
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

// xgressAddr implements net.Addr for xgress mode connections.
type xgressAddr struct {
	connId   uint32
	routerId string
	label    string
}

func (a *xgressAddr) Network() string {
	return "ziti-edge"
}

func (a *xgressAddr) String() string {
	return fmt.Sprintf("ziti-edge-router connId=%v, logical=%v", a.connId, a.label)
}

// newMarker generates a random 8-character base64 string for connection tracing.
func newMarker() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
