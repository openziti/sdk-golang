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
	"github.com/netfoundry/ziti-foundation/util/concurrenz"
	"github.com/netfoundry/ziti-sdk-golang/ziti/edge"
	"github.com/pkg/errors"
	"net"
	"time"
)

type edgeListener struct {
	serviceName string
	token       string
	edgeChan    *edgeConn
	acceptC     chan net.Conn
	closed      concurrenz.AtomicBoolean
}

func (listener *edgeListener) Network() string {
	return "ziti"
}

func (listener *edgeListener) String() string {
	return listener.serviceName
}

func (listener *edgeListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn, ok := <-listener.acceptC:
			if !ok {
				return nil, errors.New("listener is closed")
			}
			return conn, nil
		case <-time.After(time.Second):
			if listener.closed.Get() {
				return nil, errors.New("listener is closed")
			}
		}
	}

}

func (listener *edgeListener) Addr() net.Addr {
	return listener
}

func (listener *edgeListener) Close() error {
	if !listener.closed.CompareAndSwap(false, true) {
		// already closed
		return nil
	}

	listener.edgeChan.hosting.Delete(listener.token)

	edgeChan := listener.edgeChan
	defer edgeChan.Close()
	unbindRequest := edge.NewUnbindMsg(edgeChan.Id(), listener.token)
	if err := edgeChan.SendWithTimeout(unbindRequest, time.Second*5); err != nil {
		pfxlog.Logger().Errorf("unable to unbind session %v for connId %v", listener.token, edgeChan.Id())
		return err
	}

	return nil
}
