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
	"io"
	"sync"
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// newLegacyCloseTestConn builds a legacy conn wired to a mux and a test channel, the way the
// dial path does, so AcceptMessage and close behave as they do in production.
func newLegacyCloseTestConn(t *testing.T) (*edgeConnLegacy, edge.ConnMux[any], edge.SdkChannel) {
	closeNotify := make(chan struct{})
	mux := edge.NewChannelConnMapMux[any](nil)
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})
	conn := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{serviceName: "test", closeNotify: closeNotify},
		msgCh:        *edge.NewEdgeMsgChannel(testChannel, 1),
		mux:          mux,
		readQ:        NewNoopSequencer[*channel.Message](closeNotify, 4),
	}
	conn.initChunkReader()
	require.NoError(t, mux.Add(conn))
	return conn, mux, testChannel
}

func finMsg(connId uint32) *channel.Message {
	msg := edge.NewDataMsg(connId, nil)
	msg.PutUint32Header(edge.FlagsHeader, edge.FIN)
	return msg
}

func requireMuxHasConn(t *testing.T, mux edge.ConnMux[any], connId uint32, expected bool) {
	_, found := mux.GetSinks()[connId]
	require.Equal(t, expected, found)
}

// A StateClosed that arrives after the FIN has been read closes the conn on arrival; no further
// Read is needed.
func Test_LegacyConn_StateClosedAfterFinRead(t *testing.T) {
	req := require.New(t)
	conn, mux, ch := newLegacyCloseTestConn(t)

	conn.AcceptMessage(finMsg(conn.Id()), ch)
	n, err := conn.Read(make([]byte, 16))
	req.Equal(0, n)
	req.ErrorIs(err, io.EOF)
	req.False(conn.IsClosed())
	requireMuxHasConn(t, mux, conn.Id(), true)

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"), ch)
	req.True(conn.IsClosed())
	requireMuxHasConn(t, mux, conn.Id(), false)
}

// A StateClosed queued behind a FIN that has not been read yet is applied by the Read that
// reaches the FIN, even though that Read never dequeues the StateClosed itself.
func Test_LegacyConn_StateClosedQueuedBehindFin(t *testing.T) {
	req := require.New(t)
	conn, mux, ch := newLegacyCloseTestConn(t)

	conn.AcceptMessage(finMsg(conn.Id()), ch)
	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"), ch)
	req.False(conn.IsClosed())

	n, err := conn.Read(make([]byte, 16))
	req.Equal(0, n)
	req.ErrorIs(err, io.EOF)
	req.True(conn.IsClosed())
	requireMuxHasConn(t, mux, conn.Id(), false)
}

// A StateClosed with no FIN before it is still consumed in order: data queued ahead of it is
// delivered first and the conn closes when the read reaches it.
func Test_LegacyConn_StateClosedBeforeFinDeliversDataFirst(t *testing.T) {
	req := require.New(t)
	conn, mux, ch := newLegacyCloseTestConn(t)

	conn.AcceptMessage(edge.NewDataMsg(conn.Id(), []byte("hello")), ch)
	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"), ch)
	req.False(conn.IsClosed())

	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	req.NoError(err)
	req.Equal("hello", string(buf[:n]))
	req.False(conn.IsClosed())

	n, err = conn.Read(buf)
	req.Equal(0, n)
	req.ErrorIs(err, io.EOF)
	req.True(conn.IsClosed())
	requireMuxHasConn(t, mux, conn.Id(), false)
}

// The two events race on their real goroutines: the StateClosed arrives on the channel's
// receive path while the application's Read is reaching the FIN. Whichever lands second must
// close the conn, every time. Run under -race.
func Test_LegacyConn_StateClosedRacesFinRead(t *testing.T) {
	for i := 0; i < 1000; i++ {
		conn, mux, ch := newLegacyCloseTestConn(t)
		conn.AcceptMessage(finMsg(conn.Id()), ch)

		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(2)
		go func() {
			defer done.Done()
			start.Wait()
			conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"), ch)
		}()
		go func() {
			defer done.Done()
			start.Wait()
			buf := make([]byte, 16)
			for {
				if _, err := conn.Read(buf); err != nil {
					return
				}
			}
		}()
		start.Done()
		done.Wait()

		require.True(t, conn.IsClosed(), "iteration %d: conn not closed", i)
		requireMuxHasConn(t, mux, conn.Id(), false)
	}
}
