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
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream/kx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type RouterConnOwner interface {
	OnClose(factory edge.RouterConn)
}

type routerConn struct {
	routerName string
	routerAddr string
	ch         edge.SdkChannel
	mux        edge.ConnMux[any]
	owner      RouterConnOwner
}

func (conn *routerConn) GetBoolHeader(key int32) bool {
	val := conn.ch.GetChannel().Headers()[key]
	return len(val) == 1 && val[0] == 1
}

func (conn *routerConn) GetRouterAddr() string {
	return conn.routerAddr
}

func (conn *routerConn) GetRouterName() string {
	return conn.routerName
}

func (conn *routerConn) Inspect() *inspect.RouterConnInspectDetail {
	result := &inspect.RouterConnInspectDetail{
		RouterName: conn.routerName,
		RouterAddr: conn.routerAddr,
		Closed:     conn.IsClosed(),
	}
	for _, sink := range conn.mux.GetSinks() {
		if inspectable, ok := sink.(interface {
			InspectSink() *inspect.VirtualConnDetail
		}); ok {
			result.VirtualConns = append(result.VirtualConns, inspectable.InspectSink())
		}
	}
	return result
}

func (conn *routerConn) HandleClose(channel.Channel) {
	if conn.owner != nil {
		conn.owner.OnClose(conn)
	}
}

func NewRouterConn(routerName, routerAddr string, owner RouterConnOwner, inspectF func() *inspect.ContextInspectResult) edge.RouterConn {
	conn := &routerConn{
		routerAddr: routerAddr,
		routerName: routerName,
		mux:        edge.NewChannelConnMapMux[any](inspectF),
		owner:      owner,
	}

	return conn
}

func (conn *routerConn) BindChannel(binding channel.Binding) error {
	if multiChannel, ok := binding.GetChannel().(channel.MultiChannel); ok {
		conn.ch = multiChannel.GetUnderlayHandler().(edge.SdkChannel)
	} else {
		conn.ch = edge.NewSingleSdkChannel(binding.GetChannel())
	}

	conn.mux.SetSdkChannel(conn.ch)

	binding.AddReceiveHandlerF(edge.ContentTypeDial, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeStateClosed, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeTraceRoute, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeConnInspectRequest, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeBindSuccess, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeXgPayload, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeXgAcknowledgement, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeXgControl, conn.mux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeInspectRequest, conn.mux.HandleReceive)

	// Since data is the common message type, it gets to be dispatched directly
	binding.AddTypedReceiveHandler(conn.mux)
	binding.AddCloseHandler(conn.mux)
	binding.AddCloseHandler(conn)

	return nil
}

// maybeKeyPair returns a fresh key pair if the service requires encryption,
// or nil otherwise. A key-generation error is logged but not fatal — the
// connection proceeds unencrypted, matching the prior behavior.
func maybeKeyPair(service *rest_model.ServiceDetail) (*kx.KeyPair, bool) {
	if !*service.EncryptionRequired {
		return nil, false
	}
	keyPair, err := kx.NewKeyPair()
	if err != nil {
		pfxlog.Logger().Errorf("unable to setup encryption for service[%s] %v", *service.Name, err)
		return nil, false
	}
	return keyPair, true
}

// applyReplyState copies post-dial state (circuit ID, stickiness token) from
// the reply into the conn's base.
func applyReplyState(base *edgeConnBase, replyMsg *channel.Message, circuitId string) {
	base.circuitId = circuitId
	if stickinessToken, ok := replyMsg.Headers[edge.StickinessTokenHeader]; ok {
		if base.customState == nil {
			base.customState = map[int32][]byte{}
		}
		base.customState[edge.StickinessTokenHeader] = stickinessToken
	}
}

// establishClientCryptoFromReply reads the crypto method and host public key
// from the dial reply and establishes the client side of the secretstream.
// When the reply carries no host key, the connection is left unencrypted.
func establishClientCryptoFromReply(
	logger *logrus.Entry,
	replyMsg *channel.Message,
	keyPair *kx.KeyPair,
	establish func(*kx.KeyPair, []byte, edge.CryptoMethod) error,
) error {
	method, _ := replyMsg.GetByteHeader(edge.CryptoMethodHeader)
	hostPubKey := replyMsg.Headers[edge.PublicKeyHeader]
	if hostPubKey == nil {
		logger.Warn("connection is not end-to-end-encrypted")
		return nil
	}
	logger.Debug("setting up end-to-end encryption")
	if err := establish(keyPair, hostPubKey, edge.CryptoMethod(method)); err != nil {
		logger.WithError(err).Error("crypto failure")
		return err
	}
	logger.Debug("client tx encryption setup done")
	return nil
}

func (conn *routerConn) SendPosture(responses []rest_model.PostureResponseCreate) error {
	message := edge.NewPostureResponsesMsg(responses)
	sendErr := message.Send(conn.ch.GetControlSender())

	if sendErr != nil {
		return sendErr
	}

	return nil
}

func (conn *routerConn) UpdateToken(token []byte, timeout time.Duration) error {
	msg := edge.NewUpdateTokenMsg(token)
	resp, err := msg.WithTimeout(timeout).SendForReply(conn.ch.GetControlSender())

	if err != nil {
		return err
	}

	if resp.ContentType == edge.ContentTypeUpdateTokenSuccess {
		return nil
	}

	if resp.ContentType == edge.ContentTypeUpdateTokenFailure {
		err = errors.New(string(resp.Body))
		return fmt.Errorf("could not update token for router [%s]: %w", conn.GetRouterAddr(), err)
	}

	err = fmt.Errorf("invalid content type response %d, expected one of [%d, %d]", resp.ContentType, edge.ContentTypeUpdateTokenSuccess, edge.ContentTypeUpdateTokenFailure)
	return fmt.Errorf("could not update token for router [%s]: %w", conn.GetRouterAddr(), err)
}

func (conn *routerConn) NewListenConn(service *rest_model.ServiceDetail, session *rest_model.SessionDetail, options *edge.ListenOptions, envF func() xgress.Env) *edgeHostConn {
	id := conn.mux.GetNextId()

	edgeCh := &edgeHostConn{
		MsgChannel:   *edge.NewEdgeMsgChannel(conn.ch, id),
		msgMux:       conn.mux,
		serviceName:  *service.Name,
		routerInfo:   edge.EdgeRouterInfo{Name: conn.routerName, Addr: conn.routerAddr},
		keyPair:      options.KeyPair,
		crypto:       options.KeyPair != nil,
		service:      service,
		acceptC:      make(chan edge.Conn, 10),
		token:        *session.Token,
		manualStart:  options.ManualStart,
		eventHandler: options.EventHandler,
		envF:         envF,
	}

	if options.DoNotSaveDialerIdentity {
		edgeCh.flags.Set(hostConnDoNotSaveDialerIdentity, true)
	}

	// duplicate errors only happen on the server side, since the client controls ids
	if err := conn.mux.Add(edgeCh); err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", *service.Name, id, err)
	}

	pfxlog.Logger().WithField("connId", id).
		WithField("routerName", conn.routerName).
		WithField("serviceId", *service.ID).
		WithField("serviceName", *service.Name).
		Debug("created new listener connection")

	return edgeCh
}

// SupportsConnectV2 returns true if the router advertises ConnectV2 capability in its hello headers.
func (conn *routerConn) SupportsConnectV2() bool {
	return edge.IsRouterCapable(conn.ch.GetChannel().Headers(), edge.RouterCapabilityConnectV2)
}

// ConnectV2 performs a sessionless dial via the V2 protocol. The router
// authorizes locally via RDM, so no service session token is required. The
// resulting connection always uses xgress flow control.
func (conn *routerConn) ConnectV2(ctx context.Context, service *rest_model.ServiceDetail, options *edge.DialOptions, envF func() xgress.Env) (edge.Conn, error) {
	connId := conn.mux.GetNextId()
	marker := newMarker()
	keyPair, crypto := maybeKeyPair(service)

	ec := &edgeConnXgress{
		edgeConnBase: edgeConnBase{
			closeNotify: make(chan struct{}),
			serviceName: *service.Name,
			marker:      marker,
			crypto:      crypto,
			keyPair:     keyPair,
		},
		connId: connId,
	}
	ec.initChunkReader()

	logger := pfxlog.Logger().
		WithField("marker", marker).
		WithField("connId", connId).
		WithField("serviceId", *service.ID)

	var pub []byte
	if crypto {
		pub = keyPair.Public()
	}
	connectRequest := edge.NewConnectV2Msg(connId, *service.ID, edge.ServiceIdentifierById, pub, options)
	// The go sdk's V2 implementation always uses sdk xgress flow control — the returned conn
	// is always an edgeConnXgress. Override whatever the caller set on options.SdkFlowControl
	// so the router picks the xgEdgeForwarder handler and returns xgress headers.
	connectRequest.PutBoolHeader(edge.UseXgressToSdkHeader, true)
	connectRequest.PutStringHeader(edge.ConnectionMarkerHeader, marker)

	replyMsg, err := connectRequest.WithContext(ctx).SendForReply(conn.ch.GetControlSender())
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

	circuitId, _ := replyMsg.GetStringHeader(edge.CircuitIdHeader)
	applyReplyState(&ec.edgeConnBase, replyMsg, circuitId)
	logger = logger.WithField("circuitId", circuitId)

	if err := ec.setupXgressFlowControl(replyMsg, xgress.Initiator, envF, conn.ch, conn.mux); err != nil {
		return nil, err
	}

	if err := conn.mux.Add(ec); err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", *service.Name, connId, err)
	}

	if crypto {
		if err := establishClientCryptoFromReply(logger, replyMsg, keyPair, ec.establishClientCrypto); err != nil {
			_ = ec.Close()
			return nil, err
		}
	}

	logger.Debug("connected via v2")
	return ec, nil
}

// Connect performs a V1 dial. Depending on what the router grants in its
// reply, the resulting connection runs in either legacy or xgress flow-control
// mode.
func (conn *routerConn) Connect(ctx context.Context, service *rest_model.ServiceDetail, session *rest_model.SessionDetail, options *edge.DialOptions, envF func() xgress.Env) (edge.Conn, error) {
	connId := conn.mux.GetNextId()
	marker := newMarker()
	keyPair, crypto := maybeKeyPair(service)

	logger := pfxlog.Logger().
		WithField("marker", marker).
		WithField("connId", connId).
		WithField("sessionId", session.ID)

	var pub []byte
	if crypto {
		pub = keyPair.Public()
	}
	connectRequest := edge.NewConnectMsg(connId, *session.Token, pub, options)
	connectRequest.PutStringHeader(edge.ConnectionMarkerHeader, marker)
	connectRequest.PutBoolHeader(edge.UseXgressToSdkHeader, options.SdkFlowControl)

	replyMsg, err := connectRequest.WithContext(ctx).SendForReply(conn.ch.GetControlSender())
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

	circuitId, _ := replyMsg.GetStringHeader(edge.CircuitIdHeader)
	logger = logger.WithField("circuitId", circuitId)

	useXg, _ := replyMsg.GetBoolHeader(edge.UseXgressToSdkHeader)
	if useXg {
		return conn.buildV1XgressConn(logger, replyMsg, connId, marker, circuitId, keyPair, crypto, envF, *service.Name)
	}

	if defaultConnections := conn.ch.GetChannel().GetUnderlayCountsByType()[edge.ChannelTypeDefault]; defaultConnections > 1 {
		return nil, errors.New("edge connections must use sdk flow control when using multiple default connections")
	}
	return conn.buildV1LegacyConn(logger, replyMsg, connId, marker, circuitId, keyPair, crypto, *service.Name)
}

// buildV1XgressConn constructs an xgress-mode connection for a V1 dial reply.
func (conn *routerConn) buildV1XgressConn(
	logger *logrus.Entry,
	replyMsg *channel.Message,
	connId uint32,
	marker string,
	circuitId string,
	keyPair *kx.KeyPair,
	crypto bool,
	envF func() xgress.Env,
	serviceName string,
) (edge.Conn, error) {
	ec := &edgeConnXgress{
		edgeConnBase: edgeConnBase{
			closeNotify: make(chan struct{}),
			serviceName: serviceName,
			marker:      marker,
			crypto:      crypto,
			keyPair:     keyPair,
		},
		connId: connId,
	}
	ec.initChunkReader()
	applyReplyState(&ec.edgeConnBase, replyMsg, circuitId)

	if err := ec.setupXgressFlowControl(replyMsg, xgress.Initiator, envF, conn.ch, conn.mux); err != nil {
		return nil, err
	}
	if err := conn.mux.Add(ec); err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", serviceName, connId, err)
	}

	if crypto {
		if err := establishClientCryptoFromReply(logger, replyMsg, keyPair, ec.establishClientCrypto); err != nil {
			_ = ec.Close()
			return nil, err
		}
	}

	logger.Debug("connected (xgress)")
	return ec, nil
}

// buildV1LegacyConn constructs a legacy-mode connection for a V1 dial reply.
func (conn *routerConn) buildV1LegacyConn(
	logger *logrus.Entry,
	replyMsg *channel.Message,
	connId uint32,
	marker string,
	circuitId string,
	keyPair *kx.KeyPair,
	crypto bool,
	serviceName string,
) (edge.Conn, error) {
	closeNotify := make(chan struct{})
	msgCh := edge.NewEdgeMsgChannel(conn.ch, connId)
	ec := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{
			closeNotify: closeNotify,
			serviceName: serviceName,
			marker:      marker,
			crypto:      crypto,
			keyPair:     keyPair,
		},
		msgCh: *msgCh,
		mux:   conn.mux,
		readQ: NewNoopSequencer[*channel.Message](closeNotify, 4),
	}
	ec.initChunkReader()
	applyReplyState(&ec.edgeConnBase, replyMsg, circuitId)

	if err := conn.mux.Add(ec); err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", serviceName, connId, err)
	}

	if crypto {
		if err := establishClientCryptoFromReply(logger, replyMsg, keyPair, ec.establishClientCrypto); err != nil {
			_ = ec.Close()
			return nil, err
		}
	}

	logger.Debug("connected (legacy)")
	return ec, nil
}

func (conn *routerConn) Listen(service *rest_model.ServiceDetail, session *rest_model.SessionDetail, options *edge.ListenOptions, envF func() xgress.Env) (edge.RouterHostConn, error) {
	ec := conn.NewListenConn(service, session, options, envF)

	log := pfxlog.Logger().
		WithField("connId", ec.Id()).
		WithField("router", conn.routerName).
		WithField("serviceId", *service.ID).
		WithField("serviceName", *service.Name)

	if err := ec.listen(session, service, options); err != nil {
		log.WithError(err).Error("failed to establish listener")

		if closeErr := ec.Close(); closeErr != nil {
			log.WithError(closeErr).Error("failed to cleanup listener for service after failed bind")
		}
		return nil, err
	}

	if !conn.GetBoolHeader(edge.SupportsBindSuccessHeader) {
		ec.established.Store(true)
	}

	log.Debug("established listener")
	return ec, nil
}

func (conn *routerConn) Close() error {
	return conn.ch.GetChannel().Close()
}

func (conn *routerConn) IsClosed() bool {
	return conn.ch.GetChannel().IsClosed()
}
