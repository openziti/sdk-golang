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
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream/kx"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
	"sync/atomic"
	"time"
)

type edgeHostConn struct {
	edge.MsgChannel
	msgMux      edge.MsgMux
	hosting     cmap.ConcurrentMap[string, *edgeListener]
	closed      atomic.Bool
	serviceName string
	marker      string
	crypto      bool
	keyPair     *kx.KeyPair
}

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

	if msg.ContentType == edge.ContentTypeDial {
		newConnId, _ := msg.GetUint32Header(edge.RouterProvidedConnId)
		logrus.WithFields(edge.GetLoggerFields(msg)).WithField("newConnId", newConnId).Debug("received dial request")
		go conn.newChildConnection(msg)
	} else if msg.ContentType == edge.ContentTypeStateClosed {
		conn.close(true)
	} else if msg.ContentType == edge.ContentTypeBindSuccess {
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
		WithField("circuitId", token)

	err := conn.msgMux.AddMsgSink(edgeCh) // duplicate errors only happen on the server side, since client controls ids
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
			errorC:  make(chan error, 1),
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
