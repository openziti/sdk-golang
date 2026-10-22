/*
	Copyright NetFoundry Inc.

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// newWiredHostConn builds a hosting conn whose messages go out on wire.
func newWiredHostConn(id uint32, service *rest_model.ServiceDetail, wire *wireChannel) *edgeHostConn {
	return &edgeHostConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(edge.NewSingleSdkChannel(wire), id),
		msgMux:      edge.NewChannelConnMapMux[any](nil),
		serviceName: *service.Name,
		service:     service,
		acceptC:     make(chan edge.Conn, 10),
		token:       "token",
	}
}

// TestMultiListenerCloseListeners verifies that CloseListeners closes every child in parallel and
// without holding the listener lock, runs each child's close handler, and leaves the multi-listener
// open for new binds.
func TestMultiListenerCloseListeners(t *testing.T) {
	req := require.New(t)
	name := "close-listeners-test"
	service := &rest_model.ServiceDetail{Name: &name}
	ml := NewMultiListener(service, nil).(*multiListener)

	const children = 2
	// each unbind waits until every child has sent one, so closing them one at a time never ends
	unbinds := make(chan struct{}, children)
	allUnbinding := make(chan struct{})
	var unbindCount atomic.Int32
	wire := newWireChannel()
	wire.setDeliver(func(msg *channel.Message) {
		if msg.ContentType != edge.ContentTypeUnbind {
			return
		}
		// takes the lock: CloseListeners must not hold it while a child closes
		ml.GetListenerCount()
		unbinds <- struct{}{}
		if unbindCount.Add(1) == children {
			close(allUnbinding)
		}
		select {
		case <-allUnbinding:
		case <-time.After(5 * time.Second):
		}
	})

	var closeHandlers atomic.Int32
	for i := uint32(1); i <= children; i++ {
		ml.AddListener(newWiredHostConn(i, service, wire), func() { closeHandlers.Add(1) })
	}
	req.Equal(children, ml.GetListenerCount())

	closed := make(chan error, 1)
	go func() { closed <- ml.CloseListeners() }()
	select {
	case err := <-closed:
		req.NoError(err)
	case <-time.After(5 * time.Second):
		req.Fail("CloseListeners did not return")
	}
	req.Len(unbinds, children)

	req.Eventually(func() bool { return closeHandlers.Load() == children }, 5*time.Second, 10*time.Millisecond)
	req.Eventually(func() bool { return ml.GetListenerCount() == 0 }, 5*time.Second, 10*time.Millisecond)
	req.False(ml.IsClosed())
}
