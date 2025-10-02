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
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream/kx"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
)

// edgeHostConn represents a service hosting connection that acts as a "receptionist"
// for incoming client dial requests. It implements edge.MsgSink to handle service-level
// messages and manages multiple client connections through its embedded ConnMux.
//
// Architecture:
//   - Receives dial requests from clients wanting to connect to the hosted service
//   - Creates individual edgeConn instances for each accepted client connection
//   - Routes ongoing client messages directly to their respective edgeConn via msgMux
//   - Manages service lifecycle (bind, unbind, close) with the edge router
//
// Message Flow:
//   1. Client sends dial request → edgeHostConn.Accept() handles it
//   2. edgeHostConn creates new edgeConn for the client
//   3. edgeConn is added to msgMux for future message routing
//   4. Client's data messages bypass edgeHostConn and go directly to edgeConn.Accept()
//
// Thread Safety: All methods are safe for concurrent use.
type edgeHostConn struct {
	// MsgChannel provides the underlying channel communication capabilities
	// for sending messages back to the edge router (bind requests, state changes, etc.)
	edge.MsgChannel

	// msgMux manages individual client connections created from dial requests.
	// Each accepted client gets an edgeConn that is registered with this mux.
	// Future messages for specific clients are routed directly to their edgeConn.
	msgMux edge.ConnMux[any]

	// hosting maps session tokens to their corresponding edgeListener instances.
	// Each token represents a service binding session with the edge router.
	hosting cmap.ConcurrentMap[string, *edgeListener]

	// closed indicates whether this hosting connection has been terminated.
	// Used to prevent new operations on a closed connection.
	closed atomic.Bool

	// serviceName is the name of the service being hosted by this connection.
	// Used for logging and debugging purposes.
	serviceName string

	// marker is a unique identifier for this hosting connection instance.
	// Used for tracing and debugging across the distributed system.
	marker string

	// crypto indicates whether end-to-end encryption is required for client connections.
	// When true, client connections must establish encrypted sessions using keyPair.
	crypto bool

	// keyPair contains the cryptographic keys used for end-to-end encryption
	// when crypto is enabled. Used during client connection handshake.
	keyPair *kx.KeyPair

	// data stores arbitrary service-level context information that can be
	// accessed by the hosting application. This might include service configuration,
	// authentication policies, metrics collectors, or other service-wide state.
	// Unlike client-specific data in edgeConn, this context applies to the entire service.
	data atomic.Value
}

// GetData retrieves arbitrary service-level context data associated with this hosting connection.
// This allows hosting applications to store and retrieve service-wide configuration,
// state, or metadata that applies to all clients of this service.
//
// Returns:
//   - any: the stored service context data, or nil if none has been set
//
// Examples of service-level data:
//   - Service configuration and feature flags
//   - Authentication and authorization policies
//   - Metrics collectors or connection limits
//   - Custom service handlers or middleware
func (conn *edgeHostConn) GetData() any {
	return conn.data.Load()
}

// SetData stores arbitrary service-level context data for this hosting connection.
// This data persists for the lifetime of the service and can be accessed during
// client connection handling or other service operations.
//
// Parameters:
//   - data: arbitrary context data to associate with this service
//
// Thread Safety: This method is safe for concurrent use.
func (conn *edgeHostConn) SetData(data any) {
	conn.data.Store(data)
}

// Accept implements edge.MsgSink and handles service-level messages for this hosting connection.
// This method acts as the "receptionist" that processes incoming requests and manages
// the service lifecycle. It does NOT handle individual client data messages - those
// are routed directly to the appropriate edgeConn via msgMux.
//
// Handled Message Types:
//   - ContentTypeDial: Creates new client connections for dial requests
//   - ContentTypeStateClosed: Handles service shutdown notifications
//   - ContentTypeBindSuccess: Confirms service binding and notifies listeners
//   - ContentTypeConnInspectRequest: Provides service inspection data
//
// Parameters:
//   - msg: the incoming message to process
//
// Thread Safety: This method is safe for concurrent use.
func (conn *edgeHostConn) Accept(msg *channel.Message) {
	conn.TraceMsg("Accept", msg)

	if msg.ContentType == edge.ContentTypeConnInspectRequest {
		resp := edge.NewConnInspectResponse(0, edge.ConnTypeBind, conn.Inspect())
		if err := resp.ReplyTo(msg).Send(conn.GetControlSender()); err != nil {
			logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
				Error("failed to send inspect response")
		}
		return
	}

	switch msg.ContentType {
	case edge.ContentTypeDial:
		newConnId, _ := msg.GetUint32Header(edge.RouterProvidedConnId)
		circuitId, _ := msg.GetStringHeader(edge.CircuitIdHeader)
		logrus.WithFields(edge.GetLoggerFields(msg)).
			WithField("circuitId", circuitId).
			WithField("newConnId", newConnId).Debug("received dial request")
		go conn.newChildConnection(msg)
	case edge.ContentTypeStateClosed:
		conn.close(true)
	case edge.ContentTypeBindSuccess:
		for entry := range conn.hosting.IterBuffered() {
			entry.Val.established.Store(true)
			event := &edge.ListenerEvent{
				EventType: edge.ListenerEstablished,
			}
			select {
			case entry.Val.eventC <- event:
			default:
				logrus.WithFields(edge.GetLoggerFields(msg)).Warn("unable to send listener established event")
			}
		}
	}
}

func (conn *edgeHostConn) Inspect() string {
	result := map[string]interface{}{}
	result["id"] = conn.Id()
	result["serviceName"] = conn.serviceName
	result["closed"] = conn.closed.Load()
	result["encryptionRequired"] = conn.crypto

	hosting := map[string]interface{}{}
	for entry := range conn.hosting.IterBuffered() {
		hosting[entry.Key] = map[string]interface{}{
			"closed":      entry.Val.closed.Load(),
			"manualStart": entry.Val.manualStart,
			"serviceId":   *entry.Val.service.ID,
			"serviceName": *entry.Val.service.Name,
		}
	}
	result["hosting"] = hosting

	jsonOutput, err := json.Marshal(result)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("unable to marshal inspect result")
	}
	return string(jsonOutput)
}

func (conn *edgeHostConn) newChildConnection(message *channel.Message) {
	token := string(message.Body)
	circuitId, _ := message.GetStringHeader(edge.CircuitIdHeader)
	logger := pfxlog.Logger().WithField("connId", conn.Id())
	if circuitId != "" {
		logger = logger.WithField("circuitId", circuitId)
	}
	logger.WithField("token", token).Debug("logging token")

	logger.Debug("looking up listener")
	listener, found := conn.getListener(token)
	if !found {
		logger.Warn("listener not found")
		reply := edge.NewDialFailedMsg(conn.Id(), "invalid token")
		reply.ReplyTo(message)
		if err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(conn.GetControlSender()); err != nil {
			logger.WithError(err).Error("failed to send reply to dial request")
		}
		return
	}

	logger.Debug("listener found. checking for router provided connection id")

	id, routerProvidedConnId := message.GetUint32Header(edge.RouterProvidedConnId)
	if routerProvidedConnId {
		logger.Debugf("using router provided connection id %v", id)
	} else {
		id = conn.msgMux.GetNextId()
		logger.Debugf("listener found. generating id for new connection: %v", id)
	}

	sourceIdentity, _ := message.GetStringHeader(edge.CallerIdHeader)
	marker, _ := message.GetStringHeader(edge.ConnectionMarkerHeader)

	closeNotify := make(chan struct{})
	edgeCh := &edgeConn{
		closeNotify:    closeNotify,
		MsgChannel:     *edge.NewEdgeMsgChannel(conn.SdkChannel, id),
		readQ:          NewNoopSequencer[*channel.Message](closeNotify, 4),
		msgMux:         conn.msgMux,
		sourceIdentity: sourceIdentity,
		crypto:         conn.crypto,
		appData:        message.Headers[edge.AppDataHeader],
		marker:         marker,
		circuitId:      circuitId,
	}

	newConnLogger := pfxlog.Logger().
		WithField("marker", marker).
		WithField("connId", id).
		WithField("parentConnId", conn.Id()).
		WithField("token", token).
		WithField("circuitId", circuitId)

	err := conn.msgMux.Add(edgeCh) // duplicate errors only happen on the server side, since client controls ids
	if err != nil {
		conn.close(true)

		newConnLogger.WithError(err).Error("invalid conn id, already in use")
		reply := edge.NewDialFailedMsg(conn.Id(), err.Error())
		reply.ReplyTo(message)
		if err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(conn.GetControlSender()); err != nil {
			logger.WithError(err).Error("failed to send reply to dial request")
		}
		return
	}

	if err = edgeCh.setupFlowControl(message, xgress.Terminator, listener.envF); err != nil {
		logger.WithError(err).Error("failed to start flow control")
		reply := edge.NewDialFailedMsg(conn.Id(), fmt.Sprintf("failed to start flow control (%s)", err.Error()))
		reply.ReplyTo(message)
		if err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(conn.GetControlSender()); err != nil {
			logger.WithError(err).Error("failed to send reply to dial request")
		}
		return
	}

	var txHeader []byte
	if edgeCh.crypto {
		newConnLogger.Debug("setting up crypto")
		clientKey := message.Headers[edge.PublicKeyHeader]
		method, _ := message.GetByteHeader(edge.CryptoMethodHeader)

		if clientKey != nil {
			if txHeader, err = edgeCh.establishServerCrypto(conn.keyPair, clientKey, edge.CryptoMethod(method)); err != nil {
				logger.WithError(err).Error("failed to establish crypto session")
			}
		} else {
			newConnLogger.Warnf("client did not send its key. connection is not end-to-end encrypted")
		}
	}

	if err != nil {
		conn.close(true)
		newConnLogger.WithError(err).Error("failed to establish connection")
		reply := edge.NewDialFailedMsg(conn.Id(), err.Error())
		reply.ReplyTo(message)
		if err := reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendAndWaitForWire(conn.GetControlSender()); err != nil {
			logger.WithError(err).Error("failed to send reply to dial request")
		}
		return
	}

	connHandler := &newConnHandler{
		conn:                 conn,
		edgeCh:               edgeCh,
		message:              message,
		txHeader:             txHeader,
		routerProvidedConnId: routerProvidedConnId,
		circuitId:            circuitId,
	}

	if listener.manualStart {
		edgeCh.acceptCompleteHandler = connHandler
	} else if err := connHandler.dialSucceeded(); err != nil {
		logger.Debug("calling dial succeeded")
		return
	}

	listener.acceptC <- edgeCh
}

func (conn *edgeHostConn) getListener(token string) (*edgeListener, bool) {
	return conn.hosting.Get(token)
}

func (conn *edgeHostConn) HandleMuxClose() error {
	conn.close(true)
	return nil
}

func (conn *edgeHostConn) Close() error {
	conn.close(false)
	return nil
}

func (conn *edgeHostConn) close(closedByRemote bool) {
	// everything in here should be safe to execute concurrently from outside the muxer loop,
	// except the remove from mux call
	if !conn.closed.CompareAndSwap(false, true) {
		return
	}

	log := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker)
	log.Debug("close: begin")
	defer log.Debug("close: end")

	if !closedByRemote {
		msg := edge.NewStateClosedMsg(conn.Id(), "")
		if err := conn.SendState(msg); err != nil {
			log.WithError(err).Error("failed to send close message")
		}
	}

	for entry := range conn.hosting.IterBuffered() {
		listener := entry.Val
		if err := listener.close(closedByRemote); err != nil {
			log.WithError(err).WithField("serviceName", *listener.service.Name).Error("failed to close listener")
		}
	}
}

func (conn *edgeHostConn) listen(session *rest_model.SessionDetail, service *rest_model.ServiceDetail, options *edge.ListenOptions, envF func() xgress.Env) (*edgeListener, error) {
	logger := pfxlog.ContextLogger(conn.GetChannel().Label()).
		WithField("connId", conn.Id()).
		WithField("serviceName", *service.Name).
		WithField("sessionId", *session.ID)

	listener := &edgeListener{
		baseListener: baseListener{
			service: service,
			acceptC: make(chan edge.Conn, 10),
		},
		token:       *session.Token,
		edgeChan:    conn,
		manualStart: options.ManualStart,
		eventC:      options.GetEventChannel(),
		envF:        envF,
	}
	logger.Debug("adding listener for session")
	conn.hosting.Set(*session.Token, listener)

	success := false
	defer func() {
		if !success {
			logger.Debug("removing listener for session")
			conn.unbind(logger, listener.token)
		}
	}()

	logger.Debug("sending bind request to edge router")
	var pub []byte
	if conn.crypto {
		pub = conn.keyPair.Public()
	}
	bindRequest := edge.NewBindMsg(conn.Id(), *session.Token, pub, options)
	conn.TraceMsg("listen", bindRequest)
	replyMsg, err := bindRequest.WithTimeout(5 * time.Second).SendForReply(conn.GetControlSender())
	if err != nil {
		logger.WithError(err).Error("failed to bind")
		return nil, err
	}

	if replyMsg.ContentType == edge.ContentTypeStateClosed {
		msg := string(replyMsg.Body)
		logger.Errorf("bind request resulted in disconnect. msg: (%v)", msg)
		return nil, fmt.Errorf("attempt to use closed connection: %v", msg)
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		logger.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
		return nil, fmt.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
	}

	success = true
	logger.Debug("connected")

	return listener, nil
}

func (conn *edgeHostConn) unbind(logger *logrus.Entry, token string) {
	logger.Debug("starting unbind")

	conn.hosting.Remove(token)

	unbindRequest := edge.NewUnbindMsg(conn.Id(), token)
	if err := unbindRequest.WithTimeout(5 * time.Second).SendAndWaitForWire(conn.GetControlSender()); err != nil {
		logger.WithError(err).Error("unable to send unbind msg for conn")
	} else {
		logger.Debug("unbind message sent successfully")
	}
}
