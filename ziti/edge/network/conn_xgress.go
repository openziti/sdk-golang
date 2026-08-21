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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v5"
	"github.com/openziti/foundation/v2/info"
	"github.com/openziti/sdk-golang/v2/edgexg"
	"github.com/openziti/sdk-golang/v2/inspect"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/openziti/secretstream/kx"
	pkgerrors "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var _ edge.Conn = &edgeConnXgress{}

// localConnIds issues process-local diagnostic ids for xgress conns. These are
// independent of any router-assigned wire connId and are never used for mux
// dispatch; they exist so logs and inspect output can correlate a conn across
// path changes.
var localConnIds atomic.Uint32

// nextLocalConnId returns the next process-local diagnostic conn id.
func nextLocalConnId() uint32 {
	return localConnIds.Add(1)
}

// edgeConnXgress is an edge connection using xgress flow control. It is used
// for both V1 dials that negotiated SDK-side xgress and for V2 dials (which
// are xgress-only). It embeds edgeConnBase for shared state.
//
// It holds only circuit-scoped state. Router-specific state (wire connId, mux
// registration, channel senders, router-assigned xgress address) lives on the
// conn's Path(s), reachable through the xgress adapter.
type edgeConnXgress struct {
	edgeConnBase
	adapter      *MultiPathAdapter
	xg           *xgress.Xgress
	writeAdapter *xgress.WriteAdapter
	readAdapter  *xgress.ReadAdapter
	localId      uint32
}

// --- edgeConnOps implementation ---

// Id returns this conn's stable local diagnostic id. It is assigned at conn
// creation, is independent of any router-assigned wire connId and survives
// path changes. Protocol messages that address the conn on a router use the
// path's wire connId instead.
func (conn *edgeConnXgress) Id() uint32 {
	return conn.localId
}

// paths returns all paths attached to this conn, or nil if none are attached yet.
func (conn *edgeConnXgress) paths() []Path {
	if conn.adapter == nil {
		return nil
	}
	return conn.adapter.Paths()
}

// livePath returns a path that can currently carry traffic, or nil if none.
func (conn *edgeConnXgress) livePath() Path {
	for _, p := range conn.paths() {
		if !p.IsClosed() {
			return p
		}
	}
	return nil
}

// readSource supplies the chunk reader with the xgress read adapter as the
// chunk source. V2 only ever runs in xgress mode.
func (conn *edgeConnXgress) readSource() ([]byte, uint32, error) {
	return readXgressChunk(conn.readAdapter)
}

// initChunkReader wires up the chunk reader with this conn's source and
// logger. Must be called before the first Read.
func (conn *edgeConnXgress) initChunkReader() {
	conn.chunkReader = newEdgeChunkReader(conn.readSource, func() *logrus.Entry {
		return pfxlog.Logger().
			WithField("connId", conn.Id()).
			WithField("marker", conn.marker).
			WithField("circuitId", conn.circuitId)
	})
}

func (conn *edgeConnXgress) DataSink() io.Writer {
	return conn.writeAdapter
}

// --- Direct methods ---

func (conn *edgeConnXgress) TraceMsg(string, *channel.Message) {
	// no-op for xgress mode
}

// RemoteAddr returns an address capturing all of this conn's attached paths.
// Each path supplies its own address fragment.
func (conn *edgeConnXgress) RemoteAddr() net.Addr {
	addr := &xgressAddr{}
	for _, p := range conn.paths() {
		addr.paths = append(addr.paths, p.AddrFragment())
	}
	return addr
}

func (conn *edgeConnXgress) Write(data []byte) (int, error) {
	return conn.writeTo(data, conn.writeAdapter)
}

func (conn *edgeConnXgress) Close() error {
	pfxlog.Logger().WithField("connId", strconv.Itoa(int(conn.Id()))).WithField("circuitId", conn.circuitId).Debug("closing edge conn xgress")
	conn.close(true)
	return nil
}

// close performs the full close sequence for an xgress conn: atomic close
// flip, propagate FIN, cancel pending writes, and signal the xgress that the
// peer is closed. The mux entry is not removed here — xgress tear-down removes
// it once the xgress actually finishes, so in-flight payloads stay routable.
func (conn *edgeConnXgress) close(_ bool) {
	if !conn.beginClose() {
		return
	}
	log := pfxlog.Logger().WithField("connId", conn.Id()).WithField("marker", conn.marker).WithField("circuitId", conn.circuitId)
	log.Debug("close: begin")
	defer log.Debug("close: end")

	// app-initiated close is a logical end of stream: drop any recoverable hold
	// opt-in so a transport path lost during teardown can't keep the xgress open
	conn.clearRecoverable()
	_ = conn.writeAdapter.SetWriteDeadline(time.Now())
	conn.xg.PeerClosed()
}

// clearRecoverable cancels any recoverable hold opt-in. Logical end-of-stream
// events (app close, FIN, end-of-circuit received) call this so that the
// pathless hold applies only to transport loss on a still-live stream.
func (conn *edgeConnXgress) clearRecoverable() {
	if conn.adapter != nil {
		conn.adapter.ClearRecoverable()
	}
}

func (conn *edgeConnXgress) CloseWrite() error {
	if conn.sentFIN.CompareAndSwap(false, true) {
		// FIN is a logical end of stream: drop any recoverable hold
		conn.clearRecoverable()
		if conn.xg.PeerSupportsEOF() {
			conn.xg.CloseRxTimeout()
		} else {
			conn.closeWriteLegacy()
		}
	}
	return nil
}

// closeWriteLegacy half-closes the send side for a peer that does not support
// the native xgress EOF flag (an older router bridging to a legacy edge host,
// or an older SDK). Half-close historically rode as an edge FIN, transported
// transparently as a payload header that the terminating router maps back onto
// edge.FlagsHeader, so the host sees an ordinary edge FIN and stops reading.
// Moving half-close into xgress replaced that with the native EOF flag, which
// such peers don't honor; this restores the legacy signal for them. The send
// buffer is closed afterward so the FIN is the last payload transmitted.
func (conn *edgeConnXgress) closeWriteLegacy() {
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, edge.FIN)
	if _, err := conn.writeAdapter.WriteToXgress(nil, map[uint8][]byte{edgexg.PayloadFlagsHeader: flags}); err != nil {
		pfxlog.Logger().WithField("connId", conn.Id()).WithField("circuitId", conn.circuitId).
			WithError(err).Error("failed to send legacy FIN half-close")
	}
	conn.xg.CloseSendBufferWhenEmpty()
}

func (conn *edgeConnXgress) InspectSink() *inspect.VirtualConnDetail {
	return conn.edgeConnBase.InspectSink(conn.Id())
}

// Inspect returns a JSON snapshot of this xgress connection's state. circuitId
// (included via baseState) is the primary identifier; connId is the local
// diagnostic id, and per-path identity and addressing are reported under
// "paths".
func (conn *edgeConnXgress) Inspect() string {
	state := conn.baseState()
	state["connId"] = conn.Id()
	state["paths"] = conn.pathDetails()
	return marshalState(state)
}

// pathDetails reports the conn's path(s) for inspect output. Each path
// supplies its own transport-appropriate detail.
func (conn *edgeConnXgress) pathDetails() []any {
	var result []any
	for _, p := range conn.paths() {
		result = append(result, p.InspectDetail())
	}
	return result
}

// GetState returns a JSON dump of this connection's state, including the
// xgress inspect detail when an xg is attached.
func (conn *edgeConnXgress) GetState() string {
	state := conn.baseState()
	state["connId"] = conn.Id()
	state["paths"] = conn.pathDetails()
	if conn.xg != nil {
		state["xg"] = conn.xg.GetInspectDetail(true)
	}
	return marshalState(state)
}

// HandleConnInspect replies to a ContentTypeConnInspectRequest with the JSON
// state from Inspect. The reply is addressed using the wire connId of the
// path the request arrived on.
func (conn *edgeConnXgress) HandleConnInspect(path RouterPath, msg *channel.Message, ch edge.SdkChannel) {
	conn.edgeConnBase.HandleConnInspect(path.WireConnId(), conn.Inspect(), msg, ch)
}

// handleTraceRouteControl handles an incoming xgress trace route request as
// the terminator of a circuit. The request arrives wrapped in an edge
// ContentTypeXgControl message; we respond with a ControlTypeTraceRouteResponse
// and promote ControlUserVal to ReplyForHeader so the dialer's SendForReply
// correlates through the fabric. The response is addressed with the wire
// connId of the path the request arrived on.
func (conn *edgeConnXgress) handleTraceRouteControl(path RouterPath, ctrl *xgress.Control, ch edge.SdkChannel) {
	resp := ctrl.CreateTraceResponse("sdk/golang", "")
	respMsg := resp.Marshall()
	respMsg.PutUint32Header(edge.ConnIdHeader, path.WireConnId())
	if userVal, ok := ctrl.Headers.GetUint32Header(xgress.ControlUserVal); ok {
		respMsg.PutUint32Header(channel.ReplyForHeader, userVal)
	}
	if err := ch.GetControlSender().Send(respMsg); err != nil {
		pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).
			Error("failed to send xgress trace route response")
	}
}

// HandleInspect replies to a ContentTypeInspectRequest. Supports the
// "circuit:<id>" and "circuitAndStacks:<id>" inspect keys by returning the
// xgress inspect detail when the requested circuit matches this conn.
func (conn *edgeConnXgress) HandleInspect(path RouterPath, msg *channel.Message, ch edge.SdkChannel) {
	resp := &inspect.SdkInspectResponse{
		Success: true,
		Values:  make(map[string]any),
	}
	requestedValues, _, err := msg.GetStringSliceHeader(edge.InspectRequestValuesHeader)
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
		resp.Success = false
		sendInspectReply(path.WireConnId(), msg, ch, resp)
		return
	}
	for _, requested := range requestedValues {
		lc := strings.ToLower(requested)
		if strings.HasPrefix(lc, "circuit:") {
			circuitId := requested[len("circuit:"):]
			if conn.circuitId == circuitId && conn.xg != nil {
				resp.Values[requested] = conn.xg.GetInspectDetail(false)
			}
		} else if strings.HasPrefix(lc, "circuitandstacks:") {
			circuitId := requested[len("circuitAndStacks:"):]
			if conn.circuitId == circuitId && conn.xg != nil {
				resp.Values[requested] = conn.xg.GetInspectDetail(true)
			}
		}
	}
	sendInspectReply(path.WireConnId(), msg, ch, resp)
}

func (conn *edgeConnXgress) String() string {
	return fmt.Sprintf("zitiConnXgress connId=%v svcId=%v sourceIdentity=%v", conn.Id(), conn.serviceName, conn.sourceIdentity)
}

func (conn *edgeConnXgress) LocalAddr() net.Addr {
	return conn
}

func (conn *edgeConnXgress) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (conn *edgeConnXgress) SetWriteDeadline(t time.Time) error {
	return conn.writeAdapter.SetWriteDeadline(t)
}

func (conn *edgeConnXgress) SetReadDeadline(t time.Time) error {
	return conn.readAdapter.SetReadDeadline(t)
}

// onPathClosed handles the loss of a transport path (its router channel
// closed). The adapter removes the path and decides whether the xgress can
// survive: it lives on if other paths remain, or is held open if the conn is
// recoverable; otherwise it tears down, preserving today's close-on-transport-
// loss behavior for an ordinary single-path conn.
func (conn *edgeConnXgress) onPathClosed(path Path) {
	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("circuitId", conn.circuitId).WithField("routerId", path.ID())
	switch conn.adapter.RemovePath(path) {
	case pathsRemain:
		logger.Debug("path lost, other paths remain")
	case holdingForRecovery:
		logger.Info("last path lost, holding xgress open for recovery")
	case closeXgress:
		logger.Debug("last path lost, closing xgress")
		conn.closeOnPathless()
	}
}

// closeOnPathless tears down the conn and xgress when the last path is lost
// and the conn is not held open for recovery. It mirrors the pre-multi-path
// transport-loss teardown: mark the conn closed (failing pending writes) and
// hard-close the xgress. Invoked synchronously by onPathClosed and
// asynchronously by the adapter's hold-timer expiry; both are idempotent.
func (conn *edgeConnXgress) closeOnPathless() {
	conn.close(false)
	conn.xg.Close()
}

// SetRecoverable marks this conn recoverable: if its last transport path is
// lost, the xgress is held open (rather than closed) for up to timeout while
// feature code attempts to attach a replacement path. Without this opt-in,
// losing the last path closes the conn. Logical close (app Close, FIN,
// end-of-circuit) always tears down regardless of this flag.
func (conn *edgeConnXgress) SetRecoverable(timeout time.Duration) {
	conn.adapter.SetRecoverable(timeout)
}

// ClearRecoverable removes the recoverable mark and cancels any in-progress
// pathless hold. Called when recovery succeeds or is abandoned.
func (conn *edgeConnXgress) ClearRecoverable() {
	conn.adapter.ClearRecoverable()
}

func (conn *edgeConnXgress) CompleteAcceptSuccess() error {
	// the connId here is used only for logging and the DialFailed reply, which
	// the router correlates by ReplyFor without reading the connId
	return conn.edgeConnBase.CompleteAcceptSuccess(conn.Id(), conn.close)
}

// TraceRoute initiates a trace route from this xgress conn. Trace route is an
// xgress control round-trip riding the data plane, so it can run over any
// live path; if none is attached the operation fails.
func (conn *edgeConnXgress) TraceRoute(hops uint32, timeout time.Duration) (*edge.TraceRouteResult, error) {
	path := conn.livePath()
	if path == nil {
		return nil, pkgerrors.New("no live path available for trace route")
	}

	ts := uint64(info.NowInMilliseconds())
	ctrl := &xgress.Control{
		Type:      xgress.ControlTypeTraceRoute,
		CircuitId: conn.circuitId,
		Headers:   channel.Headers{},
	}
	ctrl.Headers.PutUint32Header(xgress.ControlHopCount, hops)
	ctrl.Headers.PutUint64Header(xgress.ControlTimestamp, ts)

	respCtrl, err := path.SendControlMessageForReply(ctrl, timeout)
	if err != nil {
		return nil, err
	}
	if !respCtrl.IsTypeTraceRouteResponse() {
		return nil, pkgerrors.Errorf("unexpected control type in response: %v", respCtrl.Type)
	}

	respHops, _ := respCtrl.Headers.GetUint32Header(xgress.ControlHopCount)
	respTs, _ := respCtrl.Headers.GetUint64Header(xgress.ControlTimestamp)
	elapsed := time.Duration(0)
	if respTs > 0 {
		elapsed = time.Duration(info.NowInMilliseconds()-int64(respTs)) * time.Millisecond
	}
	hopType, _ := respCtrl.Headers.GetStringHeader(xgress.ControlHopType)
	hopId, _ := respCtrl.Headers.GetStringHeader(xgress.ControlHopId)
	hopErr, _ := respCtrl.Headers.GetStringHeader(xgress.ControlError)

	return &edge.TraceRouteResult{
		Hops:    respHops,
		Time:    elapsed,
		HopType: hopType,
		HopId:   hopId,
		Error:   hopErr,
	}, nil
}

func (conn *edgeConnXgress) establishClientCrypto(keypair *kx.KeyPair, peerKey []byte, method edge.CryptoMethod) error {
	if err := conn.establishClientCryptoTo(keypair, peerKey, method, conn.writeAdapter); err != nil {
		return err
	}

	pfxlog.Logger().
		WithField("circuitId", conn.circuitId).
		WithField("marker", conn.marker).
		Debug("crypto established")

	return nil
}

// checkCircuitId validates that an inbound message belongs to this conn's
// circuit. The connId remains the mux dispatch key; this is validation only,
// turning a stale or reused connId, or a router-side misroute, into a clear
// logged fault instead of silent cross-circuit data or ack corruption. The
// mismatched message is dropped.
func (conn *edgeConnXgress) checkCircuitId(circuitId string, path RouterPath, msgType string) bool {
	if circuitId == conn.circuitId {
		return true
	}
	pfxlog.Logger().
		WithField("circuitId", conn.circuitId).
		WithField("msgCircuitId", circuitId).
		WithField("connId", path.WireConnId()).
		WithField("routerId", path.ID()).
		Errorf("inbound %s circuit id mismatch, dropping", msgType)
	return false
}

// acceptPathMessage handles incoming messages for V2 xgress connections. path
// identifies the route the message arrived on; replies that need wire-level
// conn addressing use that path's wire connId.
func (conn *edgeConnXgress) acceptPathMessage(path RouterPath, msg *channel.Message, ch edge.SdkChannel) {
	conn.TraceMsg("acceptPathMessage", msg)

	switch msg.ContentType {
	case edge.ContentTypeConnInspectRequest:
		go conn.HandleConnInspect(path, msg, ch)

	case edge.ContentTypeXgPayload:
		payload, err := xgress.UnmarshallPayload(msg)
		if err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error unmarshalling payload")
			conn.xg.Close()
			return
		}

		if !conn.checkCircuitId(payload.CircuitId, path, "payload") {
			return
		}

		payload.SetArrivalPath(path)
		if err = conn.xg.SendPayload(payload, 0, 0); err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error accepting payload")
			conn.xg.Close()
		}

	case edge.ContentTypeXgAcknowledgement:
		ack, err := xgress.UnmarshallAcknowledgement(msg)
		if err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error unmarshalling acknowledgement")
			conn.xg.Close()
			return
		}

		if !conn.checkCircuitId(ack.CircuitId, path, "acknowledgement") {
			return
		}

		ack.SetArrivalPath(path)
		if err = conn.xg.SendAcknowledgement(ack); err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("error accepting acknowledgement")
			conn.xg.Close()
		}

	case edge.ContentTypeStateClosed:
		if conn.IsClosed() {
			return
		}
		// end of circuit is a logical end of stream: drop any recoverable hold
		conn.clearRecoverable()
		// routing is not accepting more data, so we need to close the send buffer
		go conn.xg.CloseSendBuffer()
		conn.xg.CloseXgToClient()
		conn.sentFIN.Store(true) // if we're not closing until all reads are done, at least prevent more writes

	case edge.ContentTypeInspectRequest:
		go conn.HandleInspect(path, msg, ch)

	case edge.ContentTypeXgControl:
		ctrl, err := xgress.UnmarshallControl(msg)
		if err != nil {
			pfxlog.Logger().WithField("circuitId", conn.circuitId).WithError(err).Error("failed to unmarshal xgress control")
			return
		}

		if !conn.checkCircuitId(ctrl.CircuitId, path, "control") {
			return
		}

		if ctrl.IsTypeTraceRoute() {
			go conn.handleTraceRouteControl(path, ctrl, ch)
		}
		// ControlTypeTraceRouteResponse arrives only as a reply to a SendForReply
		// we initiated; the channel layer delivers it directly to that waiter, so
		// we never see it here.
	}
}

// setupXgressFlowControl sets up the conn's path, xgress adapter and xgress,
// and registers the path as a mux sink. connId is the wire connId this conn
// was dialed/accepted under on the router; it becomes the path's mux
// registration key.
func (conn *edgeConnXgress) setupXgressFlowControl(msg *channel.Message, originator xgress.Originator,
	envF func() xgress.Env, ch edge.SdkChannel, mux edge.ConnMux[any], connId uint32) error {

	// On header-validation failures here, there is nothing to clean up: the conn
	// has no xgress, no write adapter, and is not yet registered in the mux.
	// Calling Close() would NPE on the nil xg/writeAdapter.
	ctrlId, ok := msg.GetStringHeader(edge.XgressCtrlIdHeader)
	if !ok {
		return fmt.Errorf("xgress conn id header not found for circuit %s", conn.circuitId)
	}
	addr, ok := msg.GetStringHeader(edge.XgressAddressHeader)
	if !ok {
		return fmt.Errorf("xgress address header not found for circuit %s", conn.circuitId)
	}

	msgCh := edge.NewEdgeMsgChannel(ch, connId)
	sender := newRouterSender(*msgCh)
	path := &RouterChannelPath{
		conn:          conn,
		sender:        sender,
		connId:        connId,
		mux:           mux,
		ctrlSender:    ch.GetControlSender(),
		defaultSender: msgCh.GetDefaultSender(),
		routerId:      ch.GetChannel().Id(),
		channelLabel:  ch.GetChannel().LogicalName(),
		xgressAddress: xgress.Address(addr),
		xgressCtrlId:  ctrlId,
	}

	adapter := NewMultiPathAdapter(conn.circuitId, envF(), SinglePathSelector{}, path)
	adapter.conn = conn

	xg := xgress.NewXgress(conn.circuitId, ctrlId, xgress.Address(addr), adapter, originator, xgress.DefaultOptions(), nil)
	adapter.xg = xg
	xg.AddCloseHandler(adapter)
	xg.SetDataPlaneAdapter(adapter)

	conn.adapter = adapter
	conn.xg = xg
	conn.writeAdapter = xg.NewWriteAdapter()
	conn.readAdapter = xg.NewReadAdapter()

	// NB: the path is NOT registered in the mux here. The caller registers the
	// conn's path sink as the mux sink (replacing the pending placeholder on a
	// dial, or adding it on the hosting side) before calling start(), so that
	// inbound payloads/acks/controls have somewhere to land the moment the
	// xgress goes live and releases terminator-side data. Additional paths added
	// later register themselves in their own router's mux.
	return nil
}

// primaryPathSink returns the conn's initial path as a mux sink. The path is
// the conn's receive sink; the caller registers it under the conn's wire connId
// after setup.
func (conn *edgeConnXgress) primaryPathSink() edge.MsgSink[any] {
	if rcp, ok := conn.adapter.Paths()[0].(*RouterChannelPath); ok {
		return rcp
	}
	return nil
}

// start launches the xgress. It must be called only after the conn's path has
// been registered as a mux sink, so inbound messages have somewhere to dispatch
// the moment the xgress goes live (and, on the initiator, sends CircuitStart).
func (conn *edgeConnXgress) start() {
	conn.xg.Start()
}
