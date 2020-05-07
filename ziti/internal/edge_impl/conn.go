/*
	Copyright 2019 NetFoundry, Inc.

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

package edge_impl

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/secretstream"
	"github.com/netfoundry/secretstream/kx"
	"github.com/netfoundry/ziti-foundation/channel2"
	"github.com/netfoundry/ziti-foundation/util/concurrenz"
	"github.com/netfoundry/ziti-foundation/util/sequence"
	"github.com/netfoundry/ziti-foundation/util/sequencer"
	"github.com/netfoundry/ziti-sdk-golang/ziti/edge"
	"github.com/pkg/errors"
)

var connSeq *sequence.Sequence

func init() {
	connSeq = sequence.NewSequence()
}

type edgeConn struct {
	edge.MsgChannel
	readQ        sequencer.Sequencer
	leftover     []byte
	msgMux       *edge.MsgMux
	hosting      sync.Map
	closed       concurrenz.AtomicBoolean
	serviceId    string
	readDeadline time.Time

	keyPair  *kx.KeyPair
	rxKey    []byte
	receiver secretstream.Decryptor
	sender   secretstream.Encryptor
}

func (conn *edgeConn) Write(data []byte) (int, error) {
	if conn.sender != nil {
		cipherData, err := conn.sender.Push(data, secretstream.TagMessage)
		if err != nil {
			return 0, err
		}

		_, err = conn.MsgChannel.Write(cipherData)
		return len(data), err
	} else {
		return conn.MsgChannel.Write(data)
	}
}

func (conn *edgeConn) Accept(event *edge.MsgEvent) {
	conn.TraceMsg("Accept", event.Msg)
	if event.Msg.ContentType == edge.ContentTypeDial {
		pfxlog.Logger().WithFields(edge.GetLoggerFields(event.Msg)).Debug("received dial request")
		go conn.newChildConnection(event)
	} else if event.Msg.ContentType == edge.ContentTypeStateClosed && event.Seq == 0 {
		_ = conn.close(true)
	} else if err := conn.readQ.PutSequenced(event.Seq, event); err != nil {
		pfxlog.Logger().WithFields(edge.GetLoggerFields(event.Msg)).WithError(err).
			Error("error pushing edge message to sequencer")
	}
}

func (conn *edgeConn) NewConn(service string) edge.Conn {
	id := connSeq.Next()

	edgeCh := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(conn.Channel, id),
		readQ:      sequencer.NewSingleWriterSeq(DefaultMaxOutOfOrderMsgs),
		msgMux:     conn.msgMux,
		serviceId:  service,
	}

	_ = conn.msgMux.AddMsgSink(edgeCh) // duplicate errors only happen on the server side, since client controls ids
	return edgeCh
}

func (conn *edgeConn) IsClosed() bool {
	return conn.Channel.IsClosed()
}

func (conn *edgeConn) Network() string {
	return "ziti"
}

func (conn *edgeConn) String() string {
	return conn.serviceId
}

func (conn *edgeConn) LocalAddr() net.Addr {
	return &edge.Addr{MsgCh: conn.MsgChannel}
}

func (conn *edgeConn) RemoteAddr() net.Addr {
	return conn
}

func (conn *edgeConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline = t
	return nil
}

func (conn *edgeConn) HandleClose(channel2.Channel) {
	logger := pfxlog.Logger().WithField("connId", conn.Id())
	defer logger.Debug("received HandleClose from underlying channel, marking conn closed")
	conn.readQ.Close()
	conn.closed.Set(true)
}

func (conn *edgeConn) Connect(session *edge.Session) (net.Conn, error) {
	logger := pfxlog.Logger().WithField("connId", conn.Id())

	connectRequest := edge.NewConnectMsg(conn.Id(), session.Token, conn.keyPair.Public())
	conn.TraceMsg("connect", connectRequest)
	replyMsg, err := conn.SendAndWaitWithTimeout(connectRequest, 5*time.Second)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if replyMsg.ContentType == edge.ContentTypeStateClosed {
		return nil, errors.Errorf("attempt to use closed connection: %v", string(replyMsg.Body))
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		return nil, errors.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
	}

	// Is there still a race condition where we can receive the other side crypto header
	// before we have set rxkey?
	hostPubKey := replyMsg.Headers[edge.PublicKeyHeader]
	if hostPubKey != nil {
		logger = logger.WithField("session", session.Id)
		logger.Debug("setting up end-to-end encryption")
		if err = conn.establishClientCrypto(conn.keyPair, hostPubKey); err != nil {
			logger.WithError(err).Error("crypto failure")
			_ = conn.Close()
			return nil, err
		}
		logger.Debug("client tx encryption setup done")
	} else {
		logger.Warn("connection is not end-to-end-encrypted")
	}
	logger.Debug("connected")

	return conn, nil
}

func (conn *edgeConn) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte) error {
	var err error
	var rx, tx []byte

	if rx, tx, err = keypair.ClientSessionKeys(peerKey); err != nil {
		return fmt.Errorf("failed key exchange: %v", err)
	}

	var txHeader []byte
	if conn.sender, txHeader, err = secretstream.NewEncryptor(tx); err != nil {
		return fmt.Errorf("failed to establish crypto stream: %v", err)
	}

	conn.rxKey = rx

	if _, err = conn.MsgChannel.Write(txHeader); err != nil {
		return fmt.Errorf("failed to write crypto header: %v", err)
	}

	pfxlog.Logger().WithField("connId", conn.Id()).Debug("crypto established")
	return nil
}

func (conn *edgeConn) establishServerCrypto(keypair *kx.KeyPair, peerKey []byte) ([]byte, error) {
	var err error
	var rx, tx []byte

	if rx, tx, err = keypair.ServerSessionKeys(peerKey); err != nil {
		return nil, fmt.Errorf("failed key exchange: %v", err)
	}

	var txHeader []byte
	if conn.sender, txHeader, err = secretstream.NewEncryptor(tx); err != nil {
		return nil, fmt.Errorf("failed to establish crypto stream: %v", err)
	}

	conn.rxKey = rx

	return txHeader, nil
}

func (conn *edgeConn) Listen(session *edge.Session, serviceName string, options *edge.ListenOptions) (edge.Listener, error) {
	logger := pfxlog.Logger().
		WithField("connId", conn.Id()).
		WithField("service", serviceName).
		WithField("session", session.Token)

	logger.Debug("sending bind request to edge router")
	bindRequest := edge.NewBindMsg(conn.Id(), session.Token, conn.keyPair.Public(), options.Cost, options.Precedence)
	conn.TraceMsg("listen", bindRequest)
	replyMsg, err := conn.SendAndWaitWithTimeout(bindRequest, 5*time.Second)
	if err != nil {
		logger.WithError(err).Error("failed to bind")
		return nil, err
	}

	if replyMsg.ContentType == edge.ContentTypeStateClosed {
		msg := string(replyMsg.Body)
		logger.Errorf("bind request resulted in disconnect. msg: (%v)", msg)
		return nil, errors.Errorf("attempt to use closed connection: %v", msg)
	}

	if replyMsg.ContentType != edge.ContentTypeStateConnected {
		logger.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
		return nil, errors.Errorf("unexpected response to connect attempt: %v", replyMsg.ContentType)
	}

	logger.Debug("connected")
	listener := &edgeListener{
		baseListener: baseListener{
			serviceName: serviceName,
			acceptC:     make(chan net.Conn, 10),
			errorC:      make(chan error, 1),
		},
		token:    session.Token,
		edgeChan: conn,
	}
	conn.hosting.Store(session.Token, listener)
	return listener, nil
}

func (conn *edgeConn) Read(p []byte) (int, error) {
	log := pfxlog.Logger().WithField("connId", conn.Id())
	if conn.closed.Get() {
		return 0, io.EOF
	}

	log.Debugf("read buffer = %d bytes", cap(p))
	if len(conn.leftover) > 0 {
		log.Debugf("found %d leftover bytes", len(conn.leftover))
		n := copy(p, conn.leftover)
		conn.leftover = conn.leftover[n:]
		return n, nil
	}

	for {
		next, err := conn.readQ.GetNextWithDeadline(conn.readDeadline)
		if err == sequencer.ErrClosed {
			log.Debug("sequencer closed, closing connection")
			conn.closed.Set(true)
			return 0, io.EOF
		} else if err != nil {
			log.Debugf("unexepcted sequencer err (%v)", err)
			return 0, err
		}

		event := next.(*edge.MsgEvent)
		switch event.Msg.ContentType {

		case edge.ContentTypeStateClosed:
			conn.msgMux.Event(&closeConnEvent{
				conn:        conn,
				remoteClose: true,
				errorC:      make(chan error, 1),
			})
			log.Debug("received ConnState_CLOSED message, closing connection")
			continue

		case edge.ContentTypeData:
			d := event.Msg.Body
			log.Debugf("got buffer from queue %d bytes", len(d))

			// first data message should contain crypto header
			if conn.rxKey != nil {

				if len(d) != secretstream.StreamHeaderBytes {
					return 0, fmt.Errorf("failed to receive crypto header bytes: read[%d]", len(d))
				}
				conn.receiver, err = secretstream.NewDecryptor(conn.rxKey, d)
				conn.rxKey = nil
				continue
			}

			if conn.receiver != nil {
				d, _, err = conn.receiver.Pull(d)
				if err != nil {
					log.Errorf("crypto failed: %v", err)
					return 0, err
				}
			}
			if len(d) <= cap(p) {
				return copy(p, d), nil
			}
			conn.leftover = d[cap(p):]
			log.Debugf("saving %d bytes for leftover", len(conn.leftover))
			return copy(p, d), nil

		default:
			log.WithField("type", event.Msg.ContentType).Error("unexpected message")
		}
	}
}

func (conn *edgeConn) Close() error {
	event := &closeConnEvent{
		conn:        conn,
		remoteClose: false,
		errorC:      make(chan error, 1),
	}
	conn.msgMux.Event(event)
	select {
	case err := <-event.errorC:
		if err != nil {
			return err
		}
	case <-time.After(time.Second):
		return errors.New("close timed out")
	}
	return nil
}

func (conn *edgeConn) close(closedByRemote bool) error {
	if !conn.closed.CompareAndSwap(false, true) {
		return nil
	}

	log := pfxlog.Logger().WithField("connId", conn.Id())
	log.Debug("close: begin")
	defer log.Debug("close: end")

	if !closedByRemote {
		msg := edge.NewStateClosedMsg(conn.Id(), "")
		if err := conn.SendState(msg); err != nil {
			log.WithError(err).Error("failed to send close message")
		}
	}

	conn.readQ.CloseByProducer()
	go conn.msgMux.RemoveMsgSink(conn) // needs to be done async, otherwise we may deadlock

	conn.hosting.Range(func(key, value interface{}) bool {
		listener := value.(*edgeListener)
		if err := listener.Close(); err != nil {
			log.WithError(err).Errorf("failed to close listener for service %v", listener.serviceName)
		}
		return true
	})

	return nil
}

func (conn *edgeConn) getListener(token string) (*edgeListener, bool) {
	if val, found := conn.hosting.Load(token); found {
		listener, ok := val.(*edgeListener)
		return listener, ok
	}
	return nil, false
}

func (conn *edgeConn) newChildConnection(event *edge.MsgEvent) {
	message := event.Msg
	token := string(message.Body)
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("token", token)
	logger.Debug("looking up listener")
	listener, found := conn.getListener(token)
	if !found {
		logger.Warn("listener not found")
		reply := edge.NewDialFailedMsg(conn.Id(), "invalid token")
		reply.ReplyTo(message)
		if err := conn.SendWithTimeout(reply, time.Second*5); err != nil {
			logger.Errorf("Failed to send reply to dial request: (%v)", err)
		}
		return
	}

	logger.Debug("listener found. generating id for new connection")
	id := connSeq.Next()

	edgeCh := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(conn.Channel, id),
		readQ:      sequencer.NewSingleWriterSeq(DefaultMaxOutOfOrderMsgs),
		msgMux:     conn.msgMux,
	}

	_ = conn.msgMux.AddMsgSink(edgeCh) // duplicate errors only happen on the server side, since client controls ids

	newConnLogger := pfxlog.Logger().
		WithField("connId", id).
		WithField("parentConnId", conn.Id()).
		WithField("token", token)
	newConnLogger.Info("new connection established")

	clientKey := message.Headers[edge.PublicKeyHeader]
	var err error
	var txHeader []byte
	if clientKey != nil {
		newConnLogger.Debug("setting up crypto")
		if txHeader, err = edgeCh.establishServerCrypto(conn.keyPair, clientKey); err != nil {
			logger.Errorf("failed to establish crypto session %v", err)
		}
	} else {
		newConnLogger.Warnf("client did not send its key. connection is not end-to-end encrypted")
	}

	if err != nil {
		reply := edge.NewDialFailedMsg(conn.Id(), err.Error())
		reply.ReplyTo(message)
		if err := conn.SendWithTimeout(reply, time.Second*5); err != nil {
			logger.Errorf("Failed to send reply to dial request: (%v)", err)
		}
		return
	}

	reply := edge.NewDialSuccessMsg(conn.Id(), edgeCh.Id())
	reply.ReplyTo(message)
	startMsg, err := conn.SendAndWaitWithTimeout(reply, time.Second*5)
	if err != nil {
		logger.Errorf("Failed to send reply to dial request: (%v)", err)
		return
	}

	if startMsg.ContentType == edge.ContentTypeStateConnected {
		if txHeader != nil {
			newConnLogger.Debug("sending crypto header")
			if _, err = edgeCh.MsgChannel.Write(txHeader); err != nil {
				newConnLogger.Errorf("failed to write crypto header: %v", err)
			} else {
				newConnLogger.Debug("tx crypto established")
			}
		}

		listener.acceptC <- edgeCh
	} else {
		logger.Errorf("failed to receive start after dial. got %v", startMsg)
	}
}

type closeConnEvent struct {
	conn        *edgeConn
	remoteClose bool
	errorC      chan error
}

func (event *closeConnEvent) Handle(mux *edge.MsgMux) {
	if err := event.conn.close(event.remoteClose); err != nil {
		event.errorC <- err
		pfxlog.Logger().Errorf("failure closing connection. connId = %v (%v)", event.conn.Id(), err)
	}
	close(event.errorC)
}
