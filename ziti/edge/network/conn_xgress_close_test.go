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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v4"
	"github.com/openziti/metrics"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// unackedTestChannel accepts everything sent on it and never replies, so nothing an xgress sends
// through it is acknowledged.
type unackedTestChannel struct {
	NoopTestChannel
	closeNotify chan struct{}
	stalled     atomic.Bool
}

func newUnackedTestChannel() *unackedTestChannel {
	return &unackedTestChannel{closeNotify: make(chan struct{})}
}

// stall makes every later send wait for queue space that never comes, as on a channel whose peer has
// stopped reading. Nothing sent from then on is written.
func (ch *unackedTestChannel) stall() {
	ch.stalled.Store(true)
}

// Send reports s written, as a channel does once the bytes reach the wire. Once the channel is
// stalled, it waits as on a full queue until s's context ends, and returns that context's error.
func (ch *unackedTestChannel) Send(s channel.Sendable) error {
	if ch.stalled.Load() {
		<-s.Context().Done()
		return s.Context().Err()
	}
	if listener := s.SendListener(); listener != nil {
		listener.NotifyQueued()
		listener.NotifyBeforeWrite()
		listener.NotifyAfterWrite()
	}
	return nil
}

func (ch *unackedTestChannel) TrySend(s channel.Sendable) (bool, error) {
	return true, ch.Send(s)
}

func (ch *unackedTestChannel) Id() string {
	return "test-router"
}

func (ch *unackedTestChannel) LogicalName() string {
	return "test-router"
}

func (ch *unackedTestChannel) ConnectionId() string {
	return "test-connection"
}

func (ch *unackedTestChannel) CloseNotify() <-chan struct{} {
	return ch.closeNotify
}

func (ch *unackedTestChannel) IsClosed() bool {
	return false
}

type testXgressEnv struct {
	payloadIngester *xgress.PayloadIngester
	metrics         xgress.Metrics
}

func (env *testXgressEnv) GetPayloadIngester() *xgress.PayloadIngester {
	return env.payloadIngester
}

func (env *testXgressEnv) GetMetrics() xgress.Metrics {
	return env.metrics
}

// newXgressCloseTestConn builds a conn with xgress flow control, wired to a mux and an
// unacknowledging test channel the way the dial path does, and starts its xgress.
func newXgressCloseTestConn(t *testing.T) (*edgeConn, edge.ConnMux[any]) {
	t.Helper()
	return newXgressCloseTestConnOn(t, newUnackedTestChannel())
}

// newXgressCloseTestConnOn builds a conn as newXgressCloseTestConn does, on ch.
func newXgressCloseTestConnOn(t *testing.T, ch *unackedTestChannel) (*edgeConn, edge.ConnMux[any]) {
	t.Helper()

	envCloseNotify := make(chan struct{})
	t.Cleanup(func() { close(envCloseNotify) })
	envF := func() xgress.Env {
		return &testXgressEnv{
			payloadIngester: xgress.NewPayloadIngester(envCloseNotify),
			metrics:         xgress.NewMetrics(metrics.NewRegistry("test", nil)),
		}
	}

	closeNotify := make(chan struct{})
	mux := edge.NewChannelConnMapMux[any](nil)
	testChannel := edge.NewSingleSdkChannel(ch)
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:       newConnReadQ(closeNotify, defaultLegacyRxBufferSize),
		msgMux:      mux,
		serviceName: "test",
		closeNotify: closeNotify,
		circuitId:   "test-circuit",
	}
	require.NoError(t, mux.Add(conn))

	reply := edge.NewStateConnectedMsg(conn.Id())
	reply.PutBoolHeader(edge.UseXgressToSdkHeader, true)
	reply.PutStringHeader(edge.XgressCtrlIdHeader, "test-ctrl")
	reply.PutStringHeader(edge.XgressAddressHeader, "test-address")
	require.NoError(t, conn.setupFlowControl(reply, xgress.Initiator, envF))
	return conn, mux
}

// requireLeavesMux waits for conn to leave mux, which an xgress conn does once its xgress has closed.
func requireLeavesMux(t *testing.T, mux edge.ConnMux[any], conn *edgeConn) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, found := mux.GetSinks()[conn.Id()]
		return !found
	}, 5*time.Second, time.Millisecond, "the conn stayed in the mux after it closed")
}

// A conn closed locally keeps its xgress, and its mux entry, while unacknowledged payloads drain.
// A StateClosed then means routing has gone and nothing can drain, so the xgress tears down and the
// conn leaves the mux instead of retransmitting forever.
func Test_XgressConn_StateClosedAfterLocalCloseTearsDown(t *testing.T) {
	req := require.New(t)
	conn, mux := newXgressCloseTestConn(t)

	_, err := conn.Write([]byte("never acknowledged"))
	req.NoError(err)
	req.NoError(conn.Close())

	req.Never(func() bool {
		_, found := mux.GetSinks()[conn.Id()]
		return !found
	}, 250*time.Millisecond, 10*time.Millisecond, "the conn left the mux with payloads still unacknowledged")

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))

	req.Eventually(func() bool {
		_, found := mux.GetSinks()[conn.Id()]
		return !found
	}, 5*time.Second, 10*time.Millisecond, "the conn stayed in the mux after the router closed its circuit")
	req.True(conn.xgCircuit.xg.IsClosed())
}

// xgPayloadMsg returns data as the router delivers it to an xgress conn: a payload from the
// terminator with sequence seq, in an XgPayload message.
func xgPayloadMsg(seq int32, flags uint32, data []byte) *channel.Message {
	payload := &xgress.Payload{
		CircuitId: "test-circuit",
		Flags:     xgress.SetOriginatorFlag(flags, xgress.Terminator),
		Sequence:  seq,
		Data:      data,
	}
	msg := payload.Marshall()
	msg.ContentType = edge.ContentTypeXgPayload
	return msg
}

// A StateClosed that arrives while the xgress holds payloads for a stalled reader, one waiting for
// room in the read queue and more still in its receive buffer, ends the stream after them: the
// reader gets every byte the xgress received before it sees EOF, and reaching EOF closes the conn.
func Test_XgressConn_StateClosedDeliversHeldPayloads(t *testing.T) {
	req := require.New(t)
	conn, mux := newXgressCloseTestConn(t)

	payloads := xgReadQueueDepth + 3
	var expected []byte
	for i := range payloads {
		data := bytes.Repeat([]byte{byte('a' + i)}, 100)
		expected = append(expected, data...)
		conn.AcceptMessage(xgPayloadMsg(int32(i), 0, data))
	}
	conn.AcceptMessage(xgPayloadMsg(int32(payloads), uint32(xgress.PayloadFlagEOF), nil))

	req.Eventually(func() bool {
		conn.readQ.lock.Lock()
		defer conn.readQ.lock.Unlock()
		return conn.readQ.count == xgReadQueueDepth+1
	}, 5*time.Second, 10*time.Millisecond, "the xgress didn't queue a payload past the read queue depth")

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))

	req.NoError(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
	read, err := io.ReadAll(conn)
	req.NoError(err)
	req.Equal(string(expected), string(read))
	req.True(conn.IsClosed())
	requireLeavesMux(t, mux, conn)
}

// A StateClosed that arrives after the reader has reached the end of the stream closes the conn.
func Test_XgressConn_StateClosedAfterEOFReadCloses(t *testing.T) {
	req := require.New(t)
	conn, mux := newXgressCloseTestConn(t)
	conn.AcceptMessage(xgPayloadMsg(0, 0, []byte("hello")))
	conn.AcceptMessage(xgPayloadMsg(1, uint32(xgress.PayloadFlagEOF), nil))
	req.NoError(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
	read, err := io.ReadAll(conn)
	req.NoError(err)
	req.Equal("hello", string(read))

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))

	req.True(conn.IsClosed())
	requireLeavesMux(t, mux, conn)
}

// Handling a StateClosed never waits on the router channel, whose receive goroutine delivers it,
// whether the conn closes at once or once its reader has taken what the xgress still holds.
func Test_XgressConn_StateClosedDoesNotWaitOnChannel(t *testing.T) {
	t.Run("after the reader reaches the end of the stream", func(t *testing.T) {
		for i := range 20 {
			ch := newUnackedTestChannel()
			conn, mux := newXgressCloseTestConnOn(t, ch)
			conn.AcceptMessage(xgPayloadMsg(0, 0, []byte("hello")))
			conn.AcceptMessage(xgPayloadMsg(1, uint32(xgress.PayloadFlagEOF), nil))
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			read, err := io.ReadAll(conn)
			require.NoError(t, err)
			require.Equal(t, "hello", string(read))

			ch.stall()
			requireReturnsWithin(t, 2*time.Second, "AcceptMessage(StateClosed)", func() {
				conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))
			})
			require.True(t, conn.IsClosed(), "iteration %d: conn not closed", i)
			requireLeavesMux(t, mux, conn)
		}
	})

	t.Run("while the xgress holds data for the reader", func(t *testing.T) {
		for i := range 20 {
			ch := newUnackedTestChannel()
			conn, mux := newXgressCloseTestConnOn(t, ch)
			conn.AcceptMessage(xgPayloadMsg(0, 0, []byte("hello")))
			require.Eventually(t, func() bool { return conn.readQ.Size() > 0 },
				5*time.Second, time.Millisecond, "iteration %d: the xgress didn't deliver the payload", i)

			ch.stall()
			requireReturnsWithin(t, 2*time.Second, "AcceptMessage(StateClosed)", func() {
				conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))
			})
			require.False(t, conn.IsClosed(), "iteration %d: conn closed with data unread", i)

			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			read, err := io.ReadAll(conn)
			require.NoError(t, err)
			require.Equal(t, "hello", string(read))
			require.True(t, conn.IsClosed(), "iteration %d: conn not closed", i)
			requireLeavesMux(t, mux, conn)
		}
	})
}

// A StateClosed that arrives once the xgress has handed the reader the whole stream, but before the
// reader reaches its end, closes the conn when the reader does.
func Test_XgressConn_StateClosedBeforeEOFReadClosesAtEOF(t *testing.T) {
	req := require.New(t)
	conn, mux := newXgressCloseTestConn(t)
	conn.AcceptMessage(xgPayloadMsg(0, 0, []byte("hello")))
	conn.AcceptMessage(xgPayloadMsg(1, uint32(xgress.PayloadFlagEOF), nil))
	req.Eventually(conn.readQ.isClosed, 5*time.Second, 10*time.Millisecond, "the xgress didn't finish handing over the stream")

	conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))
	req.False(conn.IsClosed(), "the conn closed with data unread")
	req.NoError(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
	read, err := io.ReadAll(conn)

	req.NoError(err)
	req.Equal("hello", string(read))
	req.True(conn.IsClosed())
	requireLeavesMux(t, mux, conn)
}

// The StateClosed arrives on the channel's receive path while the xgress hands the stream to the
// reader and the reader works through it. Whichever of the end of the stream and the StateClosed
// lands second must close the conn, every time. Run under -race.
func Test_XgressConn_StateClosedRacesEOFRead(t *testing.T) {
	for i := range 1000 {
		conn, mux := newXgressCloseTestConn(t)
		conn.AcceptMessage(xgPayloadMsg(0, 0, []byte("hello")))
		conn.AcceptMessage(xgPayloadMsg(1, uint32(xgress.PayloadFlagEOF), nil))
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

		var start, done sync.WaitGroup
		start.Add(1)
		done.Go(func() {
			start.Wait()
			// Unstaggered, the StateClosed nearly always arrives before the xgress has handed over the stream.
			time.Sleep(time.Duration(i%10) * 2 * time.Microsecond)
			conn.AcceptMessage(edge.NewStateClosedMsg(conn.Id(), "test"))
		})
		done.Go(func() {
			start.Wait()
			_, _ = io.ReadAll(conn)
		})
		start.Done()
		done.Wait()

		require.True(t, conn.IsClosed(), "iteration %d: conn not closed", i)
		requireLeavesMux(t, mux, conn)
	}
}
