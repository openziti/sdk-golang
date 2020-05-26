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
	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/secretstream/kx"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/util/sequencer"
	"github.com/openziti/sdk-golang/ziti/edge"
)

const (
	// TODO: Add configuration mechanism for the SDK
	DefaultMaxOutOfOrderMsgs = 5000
)

type RouterConnOwner interface {
	OnClose(factory edge.RouterConn)
}

type routerConn struct {
	routerName string
	key        string
	ch         channel2.Channel
	msgMux     *edge.MsgMux
	owner      RouterConnOwner
}

func (conn *routerConn) Key() string {
	return conn.key
}

func (conn *routerConn) GetRouterName() string {
	return conn.routerName
}

func (conn *routerConn) HandleClose(ch channel2.Channel) {
	if conn.owner != nil {
		conn.owner.OnClose(conn)
	}
}

func NewEdgeConnFactory(routerName, key string, ch channel2.Channel, owner RouterConnOwner) edge.RouterConn {
	connFactory := &routerConn{
		key:        key,
		routerName: routerName,
		ch:         ch,
		msgMux:     edge.NewMsgMux(),
		owner:      owner,
	}

	ch.AddReceiveHandler(&edge.FunctionReceiveAdapter{
		Type:    edge.ContentTypeDial,
		Handler: connFactory.msgMux.HandleReceive,
	})

	ch.AddReceiveHandler(&edge.FunctionReceiveAdapter{
		Type:    edge.ContentTypeStateClosed,
		Handler: connFactory.msgMux.HandleReceive,
	})

	// Since data is the common message type, it gets to be dispatched directly
	ch.AddReceiveHandler(connFactory.msgMux)
	ch.AddCloseHandler(connFactory.msgMux)
	ch.AddCloseHandler(connFactory)

	return connFactory
}

func (conn *routerConn) NewConn(service string) edge.Conn {
	id := connSeq.Next()

	edgeCh := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(conn.ch, id),
		readQ:      sequencer.NewSingleWriterSeq(DefaultMaxOutOfOrderMsgs),
		msgMux:     conn.msgMux,
		serviceId:  service,
	}

	var err error
	if edgeCh.keyPair, err = kx.NewKeyPair(); err != nil {
		pfxlog.Logger().Errorf("unable to setup encryption for edgeConn[%s] %v", service, err)
	}

	err = conn.msgMux.AddMsgSink(edgeCh) // duplicate errors only happen on the server side, since client controls ids
	if err != nil {
		pfxlog.Logger().Warnf("error adding message sink %s[%d]: %v", service, id, err)
	}
	return edgeCh
}

func (conn *routerConn) Close() error {
	return conn.ch.Close()
}

func (conn *routerConn) IsClosed() bool {
	return conn.ch.IsClosed()
}
