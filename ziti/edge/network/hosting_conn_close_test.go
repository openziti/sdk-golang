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
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/metrics"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// wireTestChannel reports every send as written, so a send that waits for the wire returns at once. It
// never closes.
type wireTestChannel struct {
	NoopTestChannel
	closeNotify chan struct{}
	// writeGate, if set, holds every send's write until it is closed, as a stalled router channel would.
	writeGate   chan struct{}
	releaseOnce sync.Once
	sentLock    sync.Mutex
	// attempted records every send as it is made, and sent every write once it lands.
	attempted []*channel.Message
	sent      []*channel.Message
}

func newWireTestChannel() *wireTestChannel {
	return &wireTestChannel{closeNotify: make(chan struct{})}
}

// releaseWrites lets every held write land, and every later one land at once.
func (ch *wireTestChannel) releaseWrites() {
	ch.releaseOnce.Do(func() { close(ch.writeGate) })
}

// attempts returns the sends match accepts, in the order they were made.
func (ch *wireTestChannel) attempts(match func(*channel.Message) bool) []*channel.Message {
	ch.sentLock.Lock()
	defer ch.sentLock.Unlock()
	var result []*channel.Message
	for _, msg := range ch.attempted {
		if match(msg) {
			result = append(result, msg)
		}
	}
	return result
}

// writeIndex returns the position among the writes of the first one match accepts, or -1.
func (ch *wireTestChannel) writeIndex(match func(*channel.Message) bool) int {
	ch.sentLock.Lock()
	defer ch.sentLock.Unlock()
	for i, msg := range ch.sent {
		if match(msg) {
			return i
		}
	}
	return -1
}

func isEndOfCircuit(msg *channel.Message) bool {
	if msg.ContentType != edge.ContentTypeXgPayload {
		return false
	}
	payload, err := xgress.UnmarshallPayload(msg)
	return err == nil && payload.IsCircuitEndFlagSet()
}

func isXgClose(msg *channel.Message) bool {
	return msg.ContentType == edge.ContentTypeXgClose
}

func isUnbind(msg *channel.Message) bool {
	return msg.ContentType == edge.ContentTypeUnbind
}

func isStateClosed(msg *channel.Message) bool {
	return msg.ContentType == edge.ContentTypeStateClosed
}

func isRetransmit(msg *channel.Message) bool {
	payload, err := xgress.UnmarshallPayload(msg)
	return err == nil && payload.IsRetransmitFlagSet()
}

func (ch *wireTestChannel) CloseNotify() <-chan struct{} {
	return ch.closeNotify
}

func (ch *wireTestChannel) Id() string          { return "test-router" }
func (ch *wireTestChannel) LogicalName() string { return "test-router" }
func (ch *wireTestChannel) IsClosed() bool      { return false }

func (ch *wireTestChannel) Send(s channel.Sendable) error {
	ch.sentLock.Lock()
	ch.attempted = append(ch.attempted, s.Msg())
	ch.sentLock.Unlock()

	listener := s.SendListener()
	if listener == nil {
		return nil
	}
	written := func() {
		// As the channel does, drop a message whose write context has ended by the time it reaches the wire.
		if err := writeContextOf(s).Err(); err != nil {
			listener.NotifyErr(err)
			return
		}
		ch.sentLock.Lock()
		ch.sent = append(ch.sent, s.Msg())
		ch.sentLock.Unlock()
		listener.NotifyAfterWrite()
	}
	if ch.writeGate == nil {
		written()
		return nil
	}
	go func() {
		<-ch.writeGate
		written()
	}()
	return nil
}

// writeContextOf returns the context the channel requires to still be live when s is written: the write
// context of a message sent with SendAndWaitForQueue, otherwise the message's own.
func writeContextOf(s channel.Sendable) context.Context {
	if provider, ok := s.(interface{ WriteContext() context.Context }); ok {
		return provider.WriteContext()
	}
	return s.Context()
}

// queuedTestConn stands in for an accepted dial, and records how it was refused.
type queuedTestConn struct {
	edge.Conn
	id             uint32
	acceptFailures atomic.Int32
	closes         atomic.Int32
	// closeGate, if set, holds Close until it is closed, as a router slow to take the refusal would.
	closeGate <-chan struct{}
}

func (c *queuedTestConn) Id() uint32                 { return c.id }
func (c *queuedTestConn) CompleteAcceptFailed(error) { c.acceptFailures.Add(1) }

func (c *queuedTestConn) Close() error {
	if c.closeGate != nil {
		<-c.closeGate
	}
	c.closes.Add(1)
	return nil
}

func (c *queuedTestConn) refused() bool {
	return c.acceptFailures.Load() > 0 && c.closes.Load() > 0
}

func (c *queuedTestConn) untouched() bool {
	return c.acceptFailures.Load() == 0 && c.closes.Load() == 0
}

const testHostToken = "test-token"

// newTestHostConn builds a hosting conn the way the listen path does.
func newTestHostConn(t *testing.T) *edgeHostConn {
	return newTestHostConnOn(t, newWireTestChannel())
}

func newTestHostConnOn(t *testing.T, ch *wireTestChannel) *edgeHostConn {
	t.Helper()
	name, id, token := "test-service", "test-service-id", testHostToken
	router := &routerConn{
		routerName: "test-router",
		routerAddr: "tls:test-router:3022",
		ch:         edge.NewSingleSdkChannel(ch),
		mux:        edge.NewChannelConnMapMux[any](nil),
	}
	service := &rest_model.ServiceDetail{Name: &name}
	service.ID = &id
	hostConn := router.NewListenConn(service, &rest_model.SessionDetail{Token: &token}, &edge.ListenOptions{}, nil)

	envCloseNotify := make(chan struct{})
	t.Cleanup(func() { close(envCloseNotify) })
	env := &testXgressEnv{
		payloadIngester: xgress.NewPayloadIngester(envCloseNotify),
		metrics:         xgress.NewMetrics(metrics.NewRegistry("test", nil)),
	}
	hostConn.envF = func() xgress.Env { return env }
	return hostConn
}

// xgressDialMsg builds a dial for an xgress conn, as the router sends it.
func xgressDialMsg() *channel.Message {
	dial := channel.NewMessage(edge.ContentTypeDial, []byte(testHostToken))
	dial.PutBoolHeader(edge.UseXgressToSdkHeader, true)
	dial.PutStringHeader(edge.XgressCtrlIdHeader, "test-ctrl")
	dial.PutStringHeader(edge.XgressAddressHeader, "test-address")
	return dial
}

func requireMuxSink(t *testing.T, mux edge.ConnMux[any], connId uint32, expected edge.MsgSink[any]) {
	t.Helper()
	sink, found := mux.GetSinks()[connId]
	require.True(t, found, "conn %d must be registered", connId)
	require.Same(t, expected, sink)
}

func newTestMultiListener() *multiListener {
	name := "test-service"
	return NewMultiListener(&rest_model.ServiceDetail{Name: &name}, 0, edge.PrecedenceDefault, func() *rest_model.SessionDetail {
		return nil
	}).(*multiListener)
}

// fillAcceptQueue fills hostConn's accept queue, as dials do when the application accepts more slowly than
// they arrive.
func fillAcceptQueue(hostConn *edgeHostConn) []*queuedTestConn {
	var queued []*queuedTestConn
	for i := range cap(hostConn.acceptC) {
		conn := &queuedTestConn{id: uint32(100 + i)}
		hostConn.acceptC <- conn
		queued = append(queued, conn)
	}
	return queued
}

// requireReturns fails the test if f doesn't return within two seconds, well short of the five-second send
// bounds a wedged f could otherwise wait out. A wedged f is left blocked.
func requireReturns(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, what+" did not return")
	}
}

func waitFor(t *testing.T, c <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		require.FailNow(t, msg)
	}
}

func requireAllRefused(t *testing.T, conns []*queuedTestConn) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, conn := range conns {
			if !conn.refused() {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond, "every queued dial must be refused")
	for _, conn := range conns {
		require.EqualValues(t, 1, conn.acceptFailures.Load(), "dial %d must be refused once", conn.id)
		require.EqualValues(t, 1, conn.closes.Load(), "dial %d must be closed once", conn.id)
	}
}

// Test_HostConn_RouterCloseWithFullAcceptQueueReturns: a router's close runs on the SDK channel's receive
// goroutine, so it must not wait for the application to make room in the accept queue.
func Test_HostConn_RouterCloseWithFullAcceptQueueReturns(t *testing.T) {
	hostConn := newTestHostConn(t)
	fillAcceptQueue(hostConn)

	requireReturns(t, "the router's close", func() {
		_ = hostConn.HandleMuxClose()
	})
}

// Test_MultiListener_ForwardExitWithFullAcceptQueueRunsCloseHandler: forward closes its child on the way
// out, whatever made it exit. With a full accept queue, that close must not wait for forward to read the
// queue, or the close handler never runs and the SDK never binds to that router again. The dials left in
// the queue are refused.
func Test_MultiListener_ForwardExitWithFullAcceptQueueRunsCloseHandler(t *testing.T) {
	listener := newTestMultiListener()
	hostConn := newTestHostConn(t)
	queued := fillAcceptQueue(hostConn)
	listener.closed.Store(true) // makes forward exit before reading the queue

	closeHandlerRan := make(chan struct{})
	requireReturns(t, "forward", func() {
		listener.forward(hostConn, func() { close(closeHandlerRan) })
	})

	waitFor(t, closeHandlerRan, "the close handler must run")
	require.True(t, hostConn.flags.IsSet(hostConnClosedFlag))
	requireAllRefused(t, queued)
}

// Test_MultiListener_CloseWithFullChildAcceptQueueReturns: Close closes each child while holding the listener
// lock, and forward's close handler takes the same lock. A child close that waited on its full accept queue
// would hold the lock for good, and Close would never return. The dial forward was handing to the
// application and the queued dials are all refused.
func Test_MultiListener_CloseWithFullChildAcceptQueueReturns(t *testing.T) {
	listener := newTestMultiListener()
	hostConn := newTestHostConn(t)

	closeHandlerRan := make(chan struct{})
	listener.AddListener(hostConn, func() { close(closeHandlerRan) })

	// forward takes this one and waits for the application, which never accepts; the rest fill the queue
	inHand := &queuedTestConn{id: 99}
	hostConn.acceptC <- inHand
	require.Eventually(t, func() bool { return len(hostConn.acceptC) == 0 }, 5*time.Second, time.Millisecond)
	queued := fillAcceptQueue(hostConn)

	requireReturns(t, "the listener's Close", func() {
		_ = listener.Close()
	})

	waitFor(t, closeHandlerRan, "the close handler must run")
	requireAllRefused(t, append(queued, inHand))
}

// Test_MultiListener_CloseHandlerRunsBeforeDialsAreRefused: refusing a dial can wait on the router, so the
// close handler, which lets the listener bind again, must not wait for the refusals of the dial forward was
// handing over or of those still queued.
func Test_MultiListener_CloseHandlerRunsBeforeDialsAreRefused(t *testing.T) {
	listener := newTestMultiListener()
	hostConn := newTestHostConn(t)

	closeHandlerRan := make(chan struct{})
	listener.AddListener(hostConn, func() { close(closeHandlerRan) })

	closeGate := make(chan struct{})
	inHand := &queuedTestConn{id: 99, closeGate: closeGate}
	hostConn.acceptC <- inHand
	require.Eventually(t, func() bool { return len(hostConn.acceptC) == 0 }, 5*time.Second, time.Millisecond)
	queued := fillAcceptQueue(hostConn)
	for _, conn := range queued {
		conn.closeGate = closeGate
	}

	requireReturns(t, "the listener's Close", func() {
		_ = listener.Close()
	})
	waitFor(t, closeHandlerRan, "the close handler must not wait for the dials to be refused")

	close(closeGate)
	requireAllRefused(t, append(queued, inHand))
}

// newTestXgressConn builds and starts a hosted xgress conn on routerCh. Its circuit hasn't started.
func newTestXgressConn(t *testing.T, routerCh *wireTestChannel) (*edgeHostConn, *edgeConnXgress) {
	t.Helper()
	hostConn := newTestHostConnOn(t, routerCh)
	child, err := hostConn.buildChildConn(childConnParams{id: 7, circuitId: "test-circuit"}, true, xgressDialMsg())
	require.NoError(t, err)
	xgConn := child.(*edgeConnXgress)
	require.NoError(t, hostConn.msgMux.Add(child))
	xgConn.start()
	return hostConn, xgConn
}

// newStalledRouterXgressConn is newTestXgressConn on a router channel that holds every write until the test
// releases them or ends, with a send timeout longer than any test waits.
func newStalledRouterXgressConn(t *testing.T) (*edgeHostConn, *edgeConnXgress, *wireTestChannel) {
	t.Helper()
	routerCh := newWireTestChannel()
	routerCh.writeGate = make(chan struct{})
	t.Cleanup(routerCh.releaseWrites)
	hostConn, xgConn := newTestXgressConn(t, routerCh)
	xgConn.xgAdapter.sendTimeout = time.Minute
	return hostConn, xgConn, routerCh
}

// requireClosedOnReturn runs f, which must close xgConn's xgress, and requires the xgress to be closed the
// moment f returns, on f's goroutine. A close left to another goroutine would usually not have run yet.
func requireClosedOnReturn(t *testing.T, what string, xgConn *edgeConnXgress, f func()) {
	t.Helper()
	var closedOnReturn atomic.Bool
	requireReturns(t, what, func() {
		f()
		closedOnReturn.Store(xgConn.xg.IsClosed())
	})
	require.True(t, closedOnReturn.Load(), "%s must close the xgress before returning", what)
}

// Test_XgressConn_CloseBeforeCircuitStartReturns: a hosted xgress conn closed before its circuit starts, such
// as a refused manual-start dial, has no send loop to take an EOF. Its close must wait neither for a circuit
// start that may never come nor for a router that isn't writing, and the xgress is closed and out of the mux
// when close returns.
func Test_XgressConn_CloseBeforeCircuitStartReturns(t *testing.T) {
	for range 20 {
		hostConn, xgConn, _ := newStalledRouterXgressConn(t)

		requireClosedOnReturn(t, "closing the conn before circuit start", xgConn, func() {
			_ = xgConn.Close()
		})
		_, found := hostConn.msgMux.GetSinks()[7]
		require.False(t, found, "the closed conn must leave the mux")
	}
}

// Test_XgressConn_TeardownSendsEndOfCircuitBeforeClose: teardown sends don't hold up the close, but they still
// reach a router that is writing, end of circuit first. The router drops an end of circuit that arrives after
// the close notice, and the far side then sees a fault instead of a clean end.
func Test_XgressConn_TeardownSendsEndOfCircuitBeforeClose(t *testing.T) {
	for range 20 {
		routerCh := newWireTestChannel()
		_, xgConn := newTestXgressConn(t, routerCh)

		require.NoError(t, xgConn.Close())
		require.Eventually(t, func() bool {
			return routerCh.writeIndex(isEndOfCircuit) >= 0 && routerCh.writeIndex(isXgClose) >= 0
		}, 2*time.Second, time.Millisecond, "the router must be sent the end of circuit and the close notice")
		require.Less(t, routerCh.writeIndex(isEndOfCircuit), routerCh.writeIndex(isXgClose),
			"the end of circuit must be written before the close notice")
	}
}

// Test_XgressConn_BadMessageClosesWithoutWaitingOnRouter: a payload or acknowledgement that fails to unmarshal
// closes the xgress. Messages are handled on the router channel's receive goroutine, so the xgress must be
// closed before the next message is handled, and the close must not wait for the router to take the write.
func Test_XgressConn_BadMessageClosesWithoutWaitingOnRouter(t *testing.T) {
	for name, contentType := range map[string]int32{
		"payload":         edge.ContentTypeXgPayload,
		"acknowledgement": edge.ContentTypeXgAcknowledgement,
	} {
		t.Run(name, func(t *testing.T) {
			for range 20 {
				hostConn, xgConn, _ := newStalledRouterXgressConn(t)

				requireClosedOnReturn(t, "handling the bad "+name, xgConn, func() {
					xgConn.AcceptMessage(channel.NewMessage(contentType, nil), hostConn.SdkChannel)
				})
			}
		})
	}
}

// Test_XgressConn_StateClosedClosesWithoutWaitingOnRouter: a router's StateClosed for a conn whose send buffer
// is already closed closes the xgress. It is handled on the router channel's receive goroutine, so the xgress
// must be closed before the next message is handled, and the close must not wait for the router to take the
// write.
func Test_XgressConn_StateClosedClosesWithoutWaitingOnRouter(t *testing.T) {
	for range 20 {
		hostConn, xgConn, _ := newStalledRouterXgressConn(t)
		xgConn.xg.CloseSendBuffer()

		requireClosedOnReturn(t, "handling the router's StateClosed", xgConn, func() {
			xgConn.AcceptMessage(edge.NewStateClosedMsg(xgConn.Id(), ""), hostConn.SdkChannel)
		})
	}
}

// Test_XgAdapter_CircuitEndWaitsForItsWriteOnlyWhileOpen: an end of circuit from an open xgress ends the data
// stream, and the send buffer marks it sent once ForwardPayload returns, so ForwardPayload must not return
// before the write. One from a closed xgress is teardown, which must not wait for the wire.
func Test_XgAdapter_CircuitEndWaitsForItsWriteOnlyWhileOpen(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		_, xgConn, routerCh := newStalledRouterXgressConn(t)

		returned := make(chan struct{})
		go func() {
			defer close(returned)
			xgConn.xgAdapter.ForwardPayload(xgConn.xg.GetEndCircuit(), xgConn.xg, context.Background())
		}()
		select {
		case <-returned:
			require.FailNow(t, "the end of circuit returned before its write")
		case <-time.After(250 * time.Millisecond):
		}

		routerCh.releaseWrites()
		waitFor(t, returned, "the end of circuit must return once written")
	})

	t.Run("open, router never writes", func(t *testing.T) {
		_, xgConn, _ := newStalledRouterXgressConn(t)
		xgConn.xgAdapter.sendTimeout = 100 * time.Millisecond

		requireReturns(t, "the end of circuit once the send timeout passes", func() {
			xgConn.xgAdapter.ForwardPayload(xgConn.xg.GetEndCircuit(), xgConn.xg, context.Background())
		})
	})

	t.Run("closed", func(t *testing.T) {
		_, xgConn, _ := newStalledRouterXgressConn(t)
		xgConn.xg.Close()

		requireReturns(t, "the end of circuit from a closed xgress", func() {
			xgConn.xgAdapter.ForwardPayload(xgConn.xg.GetEndCircuit(), xgConn.xg, context.Background())
		})
	})
}

// Test_XgressConn_BufferedEndOfCircuitIsNotRetransmittedBeforeItsWrite: closing a started conn whose peer lacks
// EOF support sends end of circuit through the send buffer, which retransmits what it has marked sent and not
// had acked. While a stalled router holds the first write, nothing may retransmit it.
func Test_XgressConn_BufferedEndOfCircuitIsNotRetransmittedBeforeItsWrite(t *testing.T) {
	hostConn, xgConn, routerCh := newStalledRouterXgressConn(t)

	start := &xgress.Payload{
		CircuitId: "test-circuit",
		Flags:     xgress.SetOriginatorFlag(uint32(xgress.PayloadFlagCircuitStart), xgress.Initiator),
	}
	xgConn.AcceptMessage(start.Marshall(), hostConn.SdkChannel)
	require.Eventually(t, xgConn.xg.IsCircuitStarted, 5*time.Second, time.Millisecond)
	require.False(t, xgConn.xg.PeerSupportsEOF())

	go func() { _ = xgConn.Close() }()

	require.Eventually(t, func() bool { return len(routerCh.attempts(isEndOfCircuit)) > 0 },
		5*time.Second, time.Millisecond, "closing the conn must send end of circuit")
	// The retransmit threshold starts at 200ms and the buffer scans every 100ms.
	require.Never(t, func() bool { return len(routerCh.attempts(isEndOfCircuit)) > 1 },
		time.Second, 10*time.Millisecond, "end of circuit must not be retransmitted before its first write")
	require.False(t, isRetransmit(routerCh.attempts(isEndOfCircuit)[0]))
}

// Test_XgressConn_CloseNoticeIsWrittenAfterTheQueueDrains: the close notice goes out after the end of circuit,
// on a queue that can be slow to drain. Once queued it must be written however long that takes, not dropped
// because its send has returned or its timeout has passed.
func Test_XgressConn_CloseNoticeIsWrittenAfterTheQueueDrains(t *testing.T) {
	_, xgConn, routerCh := newStalledRouterXgressConn(t)
	xgConn.xgAdapter.sendTimeout = 100 * time.Millisecond

	require.NoError(t, xgConn.Close())
	require.Eventually(t, func() bool { return len(routerCh.attempts(isXgClose)) > 0 },
		5*time.Second, time.Millisecond, "the close notice must be queued")

	time.Sleep(3 * xgConn.xgAdapter.sendTimeout) // the queue stays stalled past the notice's timeout
	routerCh.releaseWrites()
	require.Eventually(t, func() bool { return routerCh.writeIndex(isXgClose) >= 0 },
		2*time.Second, time.Millisecond, "the close notice must be written once the queue drains")
}

// Test_XgAdapter_RetransmitIsBounded: a retransmission to a router that has stopped reading gives up within the
// send timeout, so the send buffer's retransmit goroutine can try again or see the buffer close. One requested
// after the xgress closed is refused without a send.
func Test_XgAdapter_RetransmitIsBounded(t *testing.T) {
	payload := func() *xgress.Payload {
		return &xgress.Payload{CircuitId: "test-circuit", Sequence: 1, Data: []byte("test")}
	}

	t.Run("router never writes", func(t *testing.T) {
		_, xgConn, _ := newStalledRouterXgressConn(t)
		xgConn.xgAdapter.sendTimeout = 100 * time.Millisecond

		var err error
		requireReturns(t, "the retransmission", func() {
			err = xgConn.xgAdapter.RetransmitPayload("test-address", payload())
		})
		require.Error(t, err)
	})

	t.Run("closed", func(t *testing.T) {
		_, xgConn, _ := newStalledRouterXgressConn(t)
		xgConn.xg.Close()

		var err error
		requireReturns(t, "the retransmission for a closed xgress", func() {
			err = xgConn.xgAdapter.RetransmitPayload("test-address", payload())
		})
		require.ErrorIs(t, err, errXgressClosed)
	})
}

// Test_HostConn_DuplicateLegacyConnIdLeavesLiveConnRegistered: a legacy dial whose conn id is already
// registered is refused. Its rejected conn must not be closed, since closing removes the mux entry by id, and
// that entry belongs to the live conn.
func Test_HostConn_DuplicateLegacyConnIdLeavesLiveConnRegistered(t *testing.T) {
	hostConn := newTestHostConn(t)
	live := &recordingSink{id: 7}
	require.NoError(t, hostConn.msgMux.Add(live))

	dial := xgressDialMsg()
	dial.PutBoolHeader(edge.UseXgressToSdkHeader, false)
	dial.PutUint32Header(edge.RouterProvidedConnId, 7)
	hostConn.newChildConnection(dial, hostConn.SdkChannel)

	requireMuxSink(t, hostConn.msgMux, 7, live)
}

// Test_MultiListener_ChildClosedWhileAppIsNotAcceptingRunsCloseHandler: a router can close a child while forward
// waits for the application to take a dial. forward must stop waiting and run the close handler, so the
// listener binds again, and the dial it held is refused.
func Test_MultiListener_ChildClosedWhileAppIsNotAcceptingRunsCloseHandler(t *testing.T) {
	listener := newTestMultiListener()
	hostConn := newTestHostConn(t)

	closeHandlerRan := make(chan struct{})
	listener.AddListener(hostConn, func() { close(closeHandlerRan) })

	inHand := &queuedTestConn{id: 99}
	hostConn.acceptC <- inHand
	require.Eventually(t, func() bool { return len(hostConn.acceptC) == 0 }, 5*time.Second, time.Millisecond)

	require.NoError(t, hostConn.HandleMuxClose())

	waitFor(t, closeHandlerRan, "the close handler must run")
	requireAllRefused(t, []*queuedTestConn{inHand})
}

// Test_MultiListener_UnestablishedChildIsClosedAtDeadline: a child whose bind isn't confirmed in time is
// closed, and its close handler runs so the listener can bind again.
func Test_MultiListener_UnestablishedChildIsClosedAtDeadline(t *testing.T) {
	listener := newTestMultiListener()
	listener.establishTimeout = 0
	hostConn := newTestHostConn(t)

	closeHandlerRan := make(chan struct{})
	listener.AddListener(hostConn, func() { close(closeHandlerRan) })

	waitFor(t, closeHandlerRan, "the close handler must run")
	require.True(t, hostConn.flags.IsSet(hostConnClosedFlag))
	require.Zero(t, listener.GetListenerCount())
}

// Test_HostConn_DialWaitingOnFullAcceptQueueIsRefusedOnClose: a dial waiting for room in the accept queue is
// refused when the hosting conn closes, rather than waiting for a reader that has gone.
func Test_HostConn_DialWaitingOnFullAcceptQueueIsRefusedOnClose(t *testing.T) {
	hostConn := newTestHostConn(t)
	fillAcceptQueue(hostConn)

	waiting := &queuedTestConn{id: 99}
	handedOff := make(chan struct{})
	go func() {
		defer close(handedOff)
		hostConn.queueAccepted(waiting)
	}()

	require.NoError(t, hostConn.HandleMuxClose())
	waitFor(t, handedOff, "the waiting dial must be released")
	requireAllRefused(t, []*queuedTestConn{waiting})
}

// Test_HostConn_DialQueuedAfterCloseIsRefused: a dial handed off after the hosting conn closed is refused
// whether or not it lands in the queue, since the close may already have refused what was queued.
func Test_HostConn_DialQueuedAfterCloseIsRefused(t *testing.T) {
	// The hand-off chooses at random between the free slot and the close, so repeat it to see both.
	for range 20 {
		hostConn := newTestHostConn(t)
		require.NoError(t, hostConn.HandleMuxClose())

		late := &queuedTestConn{id: 99}
		hostConn.queueAccepted(late)
		requireAllRefused(t, []*queuedTestConn{late})
		require.Zero(t, len(hostConn.acceptC))
	}
}

// Test_HostConn_CloseRefusesQueuedDials: a hosting conn can close without ever being forwarded, as when its
// bind fails after dials have arrived. Closing it refuses the dials it queued.
func Test_HostConn_CloseRefusesQueuedDials(t *testing.T) {
	hostConn := newTestHostConn(t)
	queued := fillAcceptQueue(hostConn)

	require.NoError(t, hostConn.Close())
	requireAllRefused(t, queued)
}

// Test_MultiListener_ChildAddedAfterCloseHasItsDialsRefused: a child can queue dials before it's added. If the
// listener has closed by then, the child is closed without being forwarded, and its queued dials are refused.
func Test_MultiListener_ChildAddedAfterCloseHasItsDialsRefused(t *testing.T) {
	listener := newTestMultiListener()
	require.NoError(t, listener.Close())

	hostConn := newTestHostConn(t)
	queued := fillAcceptQueue(hostConn)

	listener.AddListener(hostConn, func() {})
	require.True(t, hostConn.flags.IsSet(hostConnClosedFlag))
	require.Zero(t, listener.GetListenerCount())
	requireAllRefused(t, queued)
}

// childCloser closes a forwarded child the way one of its owners does.
type childCloser struct {
	name  string
	close func(listener *multiListener, child *edgeHostConn)
}

var childClosers = []childCloser{
	{"router", func(_ *multiListener, child *edgeHostConn) { _ = child.HandleMuxClose() }},
	{"application", func(_ *multiListener, child *edgeHostConn) { _ = child.Close() }},
	{"parent", func(listener *multiListener, _ *edgeHostConn) { _ = listener.Close() }},
}

// Test_MultiListener_DialsRacingCloseAreDeliveredOrRefused: dials keep arriving while forward hands them to an
// application that stops accepting partway, and the child is closed by the router, the application or the
// parent. Each dial must end either with the application, untouched, or refused once, and none may be left in
// the queue.
func Test_MultiListener_DialsRacingCloseAreDeliveredOrRefused(t *testing.T) {
	for _, closer := range childClosers {
		t.Run(closer.name, func(t *testing.T) {
			for i := range 30 {
				// Runs vary in how many dials the application takes, and in whether it is still accepting when
				// the child closes or has stopped, leaving forward holding a dial and the queue full.
				acceptLimit := i % 25
				closeAt := acceptLimit
				if i%2 == 1 {
					closeAt = acceptLimit / 2
				}
				runDialsRacingClose(t, acceptLimit, closeAt, closer.close)
			}
		})
	}
}

// runDialsRacingClose feeds dials to a forwarded child from several goroutines while the application accepts
// acceptLimit of them, closes the child with closeChild once the application has taken closeAt, and requires
// every dial to be delivered or refused.
func runDialsRacingClose(t *testing.T, acceptLimit, closeAt int, closeChild func(*multiListener, *edgeHostConn)) {
	t.Helper()
	const producers, dialsPerProducer = 4, 10

	listener := newTestMultiListener()
	hostConn := newTestHostConn(t)
	closeHandlerRan := make(chan struct{})
	listener.AddListener(hostConn, func() { close(closeHandlerRan) })

	closeNow := make(chan struct{})
	stopApp := make(chan struct{})
	appDone := make(chan struct{})
	delivered := map[*queuedTestConn]bool{}
	go func() {
		defer close(appDone)
		signalled := false
		for {
			if !signalled && len(delivered) >= closeAt {
				close(closeNow)
				signalled = true
			}
			if len(delivered) == acceptLimit {
				<-stopApp
				return
			}
			select {
			case conn := <-listener.acceptC:
				if conn != nil { // the parent's close wakes Accept with nil
					delivered[conn.(*queuedTestConn)] = true
				}
			case <-stopApp:
				return
			}
		}
	}()

	dials := make([]*queuedTestConn, producers*dialsPerProducer)
	for i := range dials {
		dials[i] = &queuedTestConn{id: uint32(100 + i)}
	}
	var dialing sync.WaitGroup
	for p := range producers {
		dialing.Add(1)
		go func() {
			defer dialing.Done()
			for _, dial := range dials[p*dialsPerProducer : (p+1)*dialsPerProducer] {
				hostConn.queueAccepted(dial)
			}
		}()
	}

	waitFor(t, closeNow, "the application must take its dials")
	closeChild(listener, hostConn)
	requireReturns(t, "every dial's hand-off", dialing.Wait)
	waitFor(t, closeHandlerRan, "the close handler must run")
	close(stopApp)
	waitFor(t, appDone, "the application must stop accepting")

	var undelivered []*queuedTestConn
	for _, dial := range dials {
		if !delivered[dial] {
			undelivered = append(undelivered, dial)
		}
	}
	requireAllRefused(t, undelivered)
	for dial := range delivered {
		require.True(t, dial.untouched(), "dial %d reached the application, so it must not be refused", dial.id)
	}
	require.Zero(t, len(hostConn.acceptC), "no dial may be left in the queue")
}

// Test_MultiListener_ConcurrentClosesTearDownChildOnce: the router, the application and the parent can all close
// a forwarded child at once, and forward closes it again on its way out. The child must tear down once: at most
// one unbind and one StateClosed, one run of its close handler, and each dial it held refused once.
func Test_MultiListener_ConcurrentClosesTearDownChildOnce(t *testing.T) {
	for range 50 {
		routerCh := newWireTestChannel()
		listener := newTestMultiListener()
		hostConn := newTestHostConnOn(t, routerCh)

		var closeHandlerRuns atomic.Int32
		closeHandlerRan := make(chan struct{})
		listener.AddListener(hostConn, func() {
			if closeHandlerRuns.Add(1) == 1 {
				close(closeHandlerRan)
			}
		})

		// forward takes this one and waits for the application, which never accepts; the rest fill the queue
		inHand := &queuedTestConn{id: 99}
		hostConn.acceptC <- inHand
		require.Eventually(t, func() bool { return len(hostConn.acceptC) == 0 }, 5*time.Second, time.Millisecond)
		queued := fillAcceptQueue(hostConn)

		start := make(chan struct{})
		var closing sync.WaitGroup
		for _, closer := range childClosers {
			closing.Add(1)
			go func() {
				defer closing.Done()
				<-start
				closer.close(listener, hostConn)
			}()
		}
		close(start)
		requireReturns(t, "the closes", closing.Wait)

		waitFor(t, closeHandlerRan, "the close handler must run")
		requireAllRefused(t, append(queued, inHand))
		require.EqualValues(t, 1, closeHandlerRuns.Load(), "the close handler must run once")
		unbinds := len(routerCh.attempts(isUnbind))
		require.LessOrEqual(t, unbinds, 1, "the child must unbind at most once")
		require.Len(t, routerCh.attempts(isStateClosed), unbinds, "a local close sends one StateClosed with its unbind")
	}
}

// Test_XgressConn_ConcurrentClosesTearDownOnce: the application can close a hosted xgress conn while the router
// channel's receive goroutine handles a StateClosed and then a bad payload for it. The xgress must tear down
// once, sending one end of circuit and then one close notice, and the conn must leave the mux.
func Test_XgressConn_ConcurrentClosesTearDownOnce(t *testing.T) {
	for range 20 {
		routerCh := newWireTestChannel()
		hostConn, xgConn := newTestXgressConn(t, routerCh)

		start := make(chan struct{})
		var closing sync.WaitGroup
		closing.Add(2)
		go func() {
			defer closing.Done()
			<-start
			_ = xgConn.Close()
		}()
		go func() {
			defer closing.Done()
			<-start
			// the receive goroutine handles the router's messages one at a time
			xgConn.AcceptMessage(edge.NewStateClosedMsg(xgConn.Id(), ""), hostConn.SdkChannel)
			xgConn.AcceptMessage(channel.NewMessage(edge.ContentTypeXgPayload, nil), hostConn.SdkChannel)
		}()
		close(start)
		requireReturns(t, "the closes", closing.Wait)

		require.Eventually(t, func() bool {
			return routerCh.writeIndex(isXgClose) >= 0
		}, 2*time.Second, time.Millisecond, "the close notice must be sent")
		require.Never(t, func() bool {
			return len(routerCh.attempts(isEndOfCircuit)) > 1 || len(routerCh.attempts(isXgClose)) > 1
		}, 50*time.Millisecond, 5*time.Millisecond, "the xgress must tear down once")
		require.Len(t, routerCh.attempts(isEndOfCircuit), 1, "the xgress must send an end of circuit")
		require.Less(t, routerCh.writeIndex(isEndOfCircuit), routerCh.writeIndex(isXgClose),
			"the end of circuit must be written before the close notice")
		_, found := hostConn.msgMux.GetSinks()[xgConn.Id()]
		require.False(t, found, "the closed conn must leave the mux")
	}
}
