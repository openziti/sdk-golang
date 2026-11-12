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
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// newLegacyTestConn builds a conn without SDK flow control with connId and registers it on mux, the
// way the dial path does, so messages reach it through mux.HandleReceive as they do from a router
// channel.
func newLegacyTestConn(t *testing.T, mux edge.ConnMux[any], sdkCh edge.SdkChannel, connId uint32) *edgeConn {
	t.Helper()
	closeNotify := make(chan struct{})
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(sdkCh, connId),
		readQ:       newConnReadQ(closeNotify, defaultLegacyRxBufferSize),
		msgMux:      mux,
		serviceName: "test",
		closeNotify: closeNotify,
	}
	require.NoError(t, mux.Add(conn))
	return conn
}

// A conn without SDK flow control whose reader stops taking data does not hold up the router channel's
// receive path while its read queue has room: data for another conn on the same channel is still
// dispatched and read, and the stalled conn keeps its whole backlog, in order.
func Test_LegacyConn_StalledReaderDoesNotBlockReceive(t *testing.T) {
	req := require.New(t)
	mux := edge.NewChannelConnMapMux[any](nil)
	rawCh := &NoopTestChannel{}
	sdkCh := edge.NewSingleSdkChannel(rawCh)
	stalled := newLegacyTestConn(t, mux, sdkCh, 1)
	active := newLegacyTestConn(t, mux, sdkCh, 2)

	const backlogMsgs = 1000
	const msgSize = 1024

	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		for i := range backlogMsgs {
			mux.HandleReceive(edge.NewDataMsg(stalled.Id(), bytes.Repeat([]byte{byte(i)}, msgSize)), rawCh)
		}
		mux.HandleReceive(edge.NewDataMsg(active.Id(), []byte("hello")), rawCh)
	}()

	select {
	case <-dispatched:
	case <-time.After(5 * time.Second):
		req.FailNow("receive path blocked behind a conn whose reader stopped")
	}

	req.NoError(active.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 16)
	n, err := active.Read(buf)
	req.NoError(err)
	req.Equal("hello", string(buf[:n]))

	req.Equal(int64(backlogMsgs*(msgSize+legacyMsgOverhead)), stalled.readQ.Size())
	req.NoError(stalled.SetReadDeadline(time.Now().Add(5 * time.Second)))
	backlog := make([]byte, backlogMsgs*msgSize)
	_, err = io.ReadFull(stalled, backlog)
	req.NoError(err)
	for i := range backlogMsgs {
		req.Equal(bytes.Repeat([]byte{byte(i)}, msgSize), backlog[i*msgSize:(i+1)*msgSize], "message %d", i)
	}
	req.Zero(stalled.readQ.Size())
}

// singleUnderlayChannel is a router channel with one default underlay.
type singleUnderlayChannel struct {
	NoopTestChannel
}

func (ch *singleUnderlayChannel) GetUnderlayCountsByType() map[string]int {
	return map[string]int{edge.ChannelTypeDefault: 1}
}

// Dialed and hosted conns take their read queue size from the router conn's options, and the default
// when the options leave it unset.
func Test_Conn_ReadQueueSizeComesFromRouterConnOptions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		options  RouterConnOptions
		expected int64
	}{
		{"unset", RouterConnOptions{}, defaultLegacyRxBufferSize},
		{"set", RouterConnOptions{RxBufferSizeWithoutSdkFlowControl: 64 * 1024}, 64 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := require.New(t)
			rc := NewRouterConn("router", "tls:localhost:1", nil, nil, tc.options).(*routerConn)
			rc.ch = edge.NewSingleSdkChannel(&singleUnderlayChannel{})

			serviceId, serviceName, token, encryptionRequired := "svc-id", "svc", "token", false
			service := &rest_model.ServiceDetail{Name: &serviceName, EncryptionRequired: &encryptionRequired}
			service.ID = &serviceId

			dialed := rc.NewDialConn(service)
			req.Equal(tc.expected, dialed.readQ.MaxSize())

			host := rc.NewListenConn(service, &rest_model.SessionDetail{Token: &token}, &edge.ListenOptions{ManualStart: true}, nil)
			dial := edge.NewDialMsg(host.Id(), token, "caller")
			dial.PutUint32Header(edge.RouterProvidedConnId, 100)
			host.newChildConnection(dial)
			select {
			case hosted := <-host.acceptC:
				req.Equal(tc.expected, hosted.(*edgeConn).readQ.MaxSize())
			default:
				req.FailNow("the dial was not accepted")
			}
		})
	}
}

// Closing a conn drops what its reader hadn't taken, along with anything that arrives after.
func Test_LegacyConn_CloseDropsReadQueue(t *testing.T) {
	req := require.New(t)
	mux := edge.NewChannelConnMapMux[any](nil)
	rawCh := &NoopTestChannel{}
	conn := newLegacyTestConn(t, mux, edge.NewSingleSdkChannel(rawCh), 1)

	for range 10 {
		mux.HandleReceive(edge.NewDataMsg(conn.Id(), make([]byte, 1024)), rawCh)
	}
	req.Equal(int64(10*(1024+legacyMsgOverhead)), conn.readQ.Size())

	conn.close(false)
	req.Zero(conn.readQ.Size())

	conn.queueMessage(edge.NewDataMsg(conn.Id(), make([]byte, 1024)))
	req.Zero(conn.readQ.Size())
}
