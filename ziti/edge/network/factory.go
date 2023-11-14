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
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v2"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream/kx"
)

type RouterConnOwner interface {
	OnClose(factory edge.RouterConn)
}

type routerConn struct {
	routerName string
	key        string
	ch         channel.Channel
	msgMux     edge.MsgMux
	owner      RouterConnOwner
}

func (conn *routerConn) Key() string {
	return conn.key
}

func (conn *routerConn) GetRouterName() string {
	return conn.routerName
}

func (conn *routerConn) HandleClose(channel.Channel) {
	if conn.owner != nil {
		conn.owner.OnClose(conn)
	}
}

func NewEdgeConnFactory(routerName, key string, owner RouterConnOwner) edge.RouterConn {
	connFactory := &routerConn{
		key:        key,
		routerName: routerName,
		msgMux:     edge.NewCowMapMsgMux(),
		owner:      owner,
	}

	return connFactory
}

func (conn *routerConn) BindChannel(binding channel.Binding) error {
	conn.ch = binding.GetChannel()

	binding.AddReceiveHandlerF(edge.ContentTypeDial, conn.msgMux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeStateClosed, conn.msgMux.HandleReceive)
	binding.AddReceiveHandlerF(edge.ContentTypeTraceRoute, conn.msgMux.HandleReceive)

	// Since data is the common message type, it gets to be dispatched directly
	binding.AddTypedReceiveHandler(conn.msgMux)
	binding.AddCloseHandler(conn.msgMux)
	binding.AddCloseHandler(conn)

	return nil
}

func (conn *routerConn) NewDialConn(service *rest_model.ServiceDetail, connType ConnType) *edgeConn {
	id := conn.msgMux.GetNextId()

	edgeCh := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(conn.ch, id),
		readQ:      NewNoopSequencer[*channel.Message](4),
		msgMux:     conn.msgMux,
		serviceId:  *service.Name,
		connType:   connType,
	}

	var err error
	if *service.EncryptionRequired {
		if edgeCh.keyPair, err = kx.NewKeyPair(); err == nil {
			edgeCh.crypto = true
		} else {
			pfxlog.Logger().Errorf("unable to setup encryption for edgeConn[%s] %v", *service.Name, err)
		}
	}

	err = conn.msgMux.AddMsgSink(edgeCh) // duplicate errors only happen on the server side, since client controls ids
	if err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", *service.Name, id, err)
	}
	return edgeCh
}

func (conn *routerConn) NewListenConn(service *rest_model.ServiceDetail, connType ConnType, keyPair *kx.KeyPair) *edgeConn {
	id := conn.msgMux.GetNextId()

	edgeCh := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(conn.ch, id),
		readQ:      NewNoopSequencer[*channel.Message](4),
		msgMux:     conn.msgMux,
		serviceId:  *service.Name,
		connType:   connType,
		keyPair:    keyPair,
		crypto:     keyPair != nil,
	}

	// duplicate errors only happen on the server side, since client controls ids
	if err := conn.msgMux.AddMsgSink(edgeCh); err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", *service.Name, id, err)
	}
	return edgeCh
}

func (conn *routerConn) Connect(service *rest_model.ServiceDetail, session *rest_model.SessionDetail, options *edge.DialOptions) (edge.Conn, error) {
	ec := conn.NewDialConn(service, ConnTypeDial)
	dialConn, err := ec.Connect(session, options)
	if err != nil {
		if err2 := ec.Close(); err2 != nil {
			pfxlog.Logger().Errorf("failed to cleanup connection for service '%v' (%v)", service.Name, err2)
		}
	}
	return dialConn, err
}

func (conn *routerConn) Listen(service *rest_model.ServiceDetail, session *rest_model.SessionDetail, options *edge.ListenOptions) (edge.Listener, error) {
	ec := conn.NewListenConn(service, ConnTypeBind, options.KeyPair)
	listener, err := ec.Listen(session, service, options)
	if err != nil {
		if err2 := ec.Close(); err2 != nil {
			pfxlog.Logger().WithError(err2).
				WithField("serviceName", *service.Name).
				Error("failed to cleanup listener for service after failed bind")
		}
	}
	return listener, err
}

func (conn *routerConn) Close() error {
	if !conn.ch.IsClosed() {
		return conn.ch.Close()
	}

	return nil
}

func (conn *routerConn) IsClosed() bool {
	return conn.ch.IsClosed()
}
