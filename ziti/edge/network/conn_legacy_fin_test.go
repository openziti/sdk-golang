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
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// recordingChannel records what a conn sends, and reports each message as written so that a send
// that waits for the wire returns.
type recordingChannel struct {
	NoopTestChannel
	lock sync.Mutex
	sent []*channel.Message

	// stallFirst leaves the first message never reported as written, as a stuck channel would
	stallFirst bool
}

func (ch *recordingChannel) Send(s channel.Sendable) error {
	ch.lock.Lock()
	ch.sent = append(ch.sent, s.Msg())
	stall := ch.stallFirst && len(ch.sent) == 1
	ch.lock.Unlock()

	if stall {
		return nil
	}

	if l := s.SendListener(); l != nil {
		l.NotifyQueued()
		l.NotifyBeforeWrite()
		l.NotifyAfterWrite()
	}
	return nil
}

func (ch *recordingChannel) IsClosed() bool { return false }

// CloseNotify never fires: the channel stays open. A nil channel blocks forever in a select.
func (ch *recordingChannel) CloseNotify() <-chan struct{} { return nil }

// kinds describes what was sent, in order: "fin" for a data message carrying the FIN flag, "data"
// for any other data message, "closed" for a StateClosed.
func (ch *recordingChannel) kinds() []string {
	ch.lock.Lock()
	defer ch.lock.Unlock()

	var result []string
	for _, msg := range ch.sent {
		switch msg.ContentType {
		case edge.ContentTypeData:
			if flags, _ := msg.GetUint32Header(edge.FlagsHeader); flags&edge.FIN != 0 {
				result = append(result, "fin")
			} else {
				result = append(result, "data")
			}
		case edge.ContentTypeStateClosed:
			result = append(result, "closed")
		default:
			result = append(result, "other")
		}
	}
	return result
}

func newRecordingLegacyConn(t *testing.T) (*edgeConnLegacy, *recordingChannel, edge.SdkChannel) {
	closeNotify := make(chan struct{})
	mux := edge.NewChannelConnMapMux[any](nil)
	rc := &recordingChannel{}
	sdkChannel := edge.NewSingleSdkChannel(rc)
	conn := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{serviceName: "test", closeNotify: closeNotify},
		msgCh:        *edge.NewEdgeMsgChannel(sdkChannel, 1),
		mux:          mux,
		readQ:        NewNoopSequencer[*channel.Message](closeNotify, 4),
	}
	conn.initChunkReader()
	require.NoError(t, mux.Add(conn))
	return conn, rc, sdkChannel
}

// A close with no FIN before it is how an abort looks to the peer, so a Close that is not an abort
// ends its data first.
func Test_LegacyConn_CloseSendsFinBeforeStateClosed(t *testing.T) {
	conn, ch, _ := newRecordingLegacyConn(t)

	require.NoError(t, conn.Close())

	require.Equal(t, []string{"fin", "closed"}, ch.kinds())
}

// The FIN is sent once: a Close after CloseWrite adds only the StateClosed.
func Test_LegacyConn_CloseAfterCloseWriteSendsFinOnce(t *testing.T) {
	conn, ch, _ := newRecordingLegacyConn(t)

	require.NoError(t, conn.CloseWrite())
	require.NoError(t, conn.Close())

	require.Equal(t, []string{"fin", "closed"}, ch.kinds())
}

// A second Close sends nothing.
func Test_LegacyConn_SecondCloseSendsNothing(t *testing.T) {
	conn, ch, _ := newRecordingLegacyConn(t)

	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())

	require.Equal(t, []string{"fin", "closed"}, ch.kinds())
}

// Close must not hang because its FIN cannot get onto a stuck channel: it gives the FIN a bounded
// time, then closes anyway.
func Test_LegacyConn_CloseDoesNotHangWhenTheFinIsStuck(t *testing.T) {
	defer func(old time.Duration) { closeFinTimeout = old }(closeFinTimeout)
	closeFinTimeout = 100 * time.Millisecond

	conn, ch, _ := newRecordingLegacyConn(t)
	ch.stallFirst = true

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = conn.Close()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung waiting for its FIN to be written")
	}
	require.True(t, conn.IsClosed())
	require.Equal(t, []string{"fin", "closed"}, ch.kinds())
}

// A close the peer started is not answered with a FIN: the conn is already gone as far as the peer
// is concerned. The peer's StateClosed is only applied when a Read reaches it.
func Test_LegacyConn_CloseAfterPeerClosedSendsNothing(t *testing.T) {
	conn, ch, sdkChannel := newRecordingLegacyConn(t)

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"), sdkChannel)
	_, err := conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
	require.True(t, conn.IsClosed())

	require.NoError(t, conn.Close())

	require.Empty(t, ch.kinds())
}
