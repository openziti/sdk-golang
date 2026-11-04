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

	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// newLegacyTestConn builds a conn without SDK flow control with connId and registers it on mux, the
// way the dial path does, so messages reach it through mux.HandleReceive as they do from a router
// channel.
func newLegacyTestConn(t *testing.T, mux edge.ConnMux[any], sdkCh edge.SdkChannel, connId uint32) *edgeConn {
	closeNotify := make(chan struct{})
	t.Cleanup(func() { close(closeNotify) })
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(sdkCh, connId),
		readQ:       NewNoopSequencer[*channel.Message](closeNotify),
		msgMux:      mux,
		serviceName: "test",
		closeNotify: closeNotify,
	}
	require.NoError(t, mux.Add(conn))
	return conn
}

// A conn without SDK flow control whose reader stops taking data does not hold up the router channel's receive path:
// data for another conn on the same channel is still dispatched and read, and the stalled conn keeps
// its whole backlog, in order.
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

	req.Equal(int64(backlogMsgs*msgSize), stalled.backlogBytes.Load())
	req.NoError(stalled.SetReadDeadline(time.Now().Add(5 * time.Second)))
	backlog := make([]byte, backlogMsgs*msgSize)
	_, err = io.ReadFull(stalled, backlog)
	req.NoError(err)
	for i := range backlogMsgs {
		req.Equal(bytes.Repeat([]byte{byte(i)}, msgSize), backlog[i*msgSize:(i+1)*msgSize], "message %d", i)
	}
	req.Zero(stalled.backlogBytes.Load())
}

func Test_BacklogWarningCrossed(t *testing.T) {
	const w = legacyBacklogWarnBytes
	tests := []struct {
		name          string
		before, after int64
		crossed       bool
	}{
		{name: "below the threshold", before: 0, after: w - 1},
		{name: "reaches the threshold", before: w - 1, after: w, crossed: true},
		{name: "grows past the threshold in one message", before: 0, after: 3 * w, crossed: true},
		{name: "grows between the threshold and its double", before: w, after: 2*w - 1},
		{name: "reaches the double", before: 2*w - 1, after: 2 * w, crossed: true},
		{name: "grows between the double and the quadruple", before: 2 * w, after: 4*w - 1},
		{name: "reaches the quadruple", before: 4*w - 1, after: 4 * w, crossed: true},
		{name: "unchanged at the threshold", before: w, after: w},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.crossed, backlogWarningCrossed(test.before, test.after))
		})
	}
}
