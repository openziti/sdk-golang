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
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/v2/pb/edge_client_pb"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

// takeoverRequestTimeout bounds a single takeover request/reply exchange with one
// candidate router, so a slow or unresponsive candidate doesn't consume the whole
// recovery window; the loop then moves on to the next candidate.
const takeoverRequestTimeout = 5 * time.Second

// takeoverOutcome is the result of a single takeover attempt against one
// candidate router, and tells the recovery loop whether to stop, try the next
// candidate, or give up entirely.
type takeoverOutcome int

const (
	// takeoverRetryable means this candidate did not work but another might
	// (router unreachable, busy, route install failed): try the next candidate.
	takeoverRetryable takeoverOutcome = iota
	// takeoverSucceeded means the circuit was reattached via this candidate: the
	// new path is live and recovery is done.
	takeoverSucceeded
	// takeoverFatal means the takeover was rejected in a way retrying elsewhere
	// cannot fix (token rejected, circuit gone, not reroutable): surface closed.
	takeoverFatal
)

// DefaultRerouteRecoveryWindow is how long a reroutable conn holds its xgress
// open after losing its last path while it attempts to reattach the circuit via
// another router. It is kept slightly under the controller's Limbo grace period
// so the SDK gives up just before the controller tears the circuit down, sparing
// a wasted takeover round trip that would only find the circuit gone.
const DefaultRerouteRecoveryWindow = 9 * time.Second

// RerouteCandidateProvider supplies the edge routers a conn can attempt to
// reattach its circuit through, best-first (by measured latency), filtered to
// those advertising SDK-reroute support. It is implemented by the ziti Context
// and injected into a reroutable conn at dial time, so the recovery loop can
// select candidates without the conn holding a back-reference to the Context.
type RerouteCandidateProvider interface {
	// GetRerouteCandidates returns router connections capable of taking over a
	// circuit for the given service, ordered best-first. Candidates may need to
	// be connected on demand, so this can block.
	GetRerouteCandidates(serviceId string) []edge.RouterConn
}

// markReroutable records the controller-signed reroute token and candidate
// provider for a conn and opts the conn into the recoverable hold, so losing its
// last path holds the xgress open for a recovery attempt rather than closing it.
// A conn is reroutable exactly while it holds a non-empty token.
//
// SetRecoverable must stay last. owner is a plain field, and the xgress is
// already running by the time this is called, so a path can be lost
// concurrently. The adapter lock taken here is what publishes owner and the
// token to the recovery goroutine: a path loss that observes the recoverable
// mark is ordered after both writes, and one that arrives earlier sees an
// unrecoverable conn and closes it without ever reading them.
func (conn *edgeConnXgress) markReroutable(token string, owner RerouteCandidateProvider) {
	conn.setRerouteToken(token)
	conn.owner = owner
	conn.SetRecoverable(DefaultRerouteRecoveryWindow)
}

// isReroutable reports whether this conn can attempt SDK reroute, i.e. it holds
// a current reroute token and a back-reference to its owning Context.
func (conn *edgeConnXgress) isReroutable() bool {
	return conn.owner != nil && conn.getRerouteToken() != ""
}

// recoverCircuit attempts to reattach this conn's circuit via another router
// after its last path was lost, so the xgress (held open by the recoverable
// hold) can resume rather than close. It walks the owner's best-first takeover
// candidates, attempting each until one succeeds. If none do, or the takeover is
// fatally rejected, it clears the recoverable hold to surface the conn closed
// promptly rather than waiting out the hold timer. It is guarded so only one
// recovery runs at a time.
//
// Callers must only invoke this on a reroutable conn; the isReroutable check
// below is a backstop rather than the intended gate, since this runs in its own
// goroutine where a nil owner would take down the process instead of just
// failing the conn. Returning without resolving the hold leaves the xgress held
// until the hold timer closes it.
func (conn *edgeConnXgress) recoverCircuit() {
	if !conn.isReroutable() {
		return
	}

	if !conn.recovering.CompareAndSwap(false, true) {
		return
	}
	defer conn.recovering.Store(false)

	logger := pfxlog.Logger().WithField("connId", conn.Id()).WithField("circuitId", conn.circuitId)

	for _, candidate := range conn.owner.GetRerouteCandidates(conn.serviceId) {
		if conn.IsClosed() {
			return
		}
		switch conn.attemptTakeover(candidate) {
		case takeoverSucceeded:
			logger.WithField("routerId", candidate.GetRouterName()).Info("circuit recovered via reroute")
			return
		case takeoverFatal:
			logger.Warn("reroute rejected as fatal, surfacing conn closed")
			conn.ClearRecoverable()
			return
		case takeoverRetryable:
			// try the next candidate
		}
	}

	logger.Warn("no reroute candidate accepted takeover, surfacing conn closed")
	conn.ClearRecoverable()
}

// rerouteTakeoverTarget is a candidate that can take over a reroutable circuit.
// Every router-channel connection satisfies it; a candidate that cannot (e.g. a
// future non-router path type surfaced as a takeover candidate) is skipped by
// the recovery loop rather than assumed to be a router.
type rerouteTakeoverTarget interface {
	takeoverCircuit(ec *edgeConnXgress, token string) takeoverOutcome
}

// attemptTakeover tries to reattach this conn's circuit through a single
// candidate, adding the resulting path on success. A candidate that cannot take
// over a circuit is skipped as retryable.
func (conn *edgeConnXgress) attemptTakeover(candidate edge.RouterConn) takeoverOutcome {
	target, ok := candidate.(rerouteTakeoverTarget)
	if !ok {
		return takeoverRetryable
	}
	return target.takeoverCircuit(conn, conn.getRerouteToken())
}

// takeoverOutcomeForResult maps a takeover reply's result code to the recovery
// loop's disposition: success stops the loop, transient failures move to the
// next candidate, and everything else (bad token, not reroutable, circuit gone,
// or an unrecognized code) is fatal because no other candidate can fix it.
func takeoverOutcomeForResult(code uint32) takeoverOutcome {
	switch edge_client_pb.TakeoverResult(code) {
	case edge_client_pb.TakeoverResult_TakeoverSuccess:
		return takeoverSucceeded
	case edge_client_pb.TakeoverResult_TakeoverOwnerUnreachable,
		edge_client_pb.TakeoverResult_TakeoverBusy,
		edge_client_pb.TakeoverResult_TakeoverRouteInstallFailed:
		return takeoverRetryable
	default:
		return takeoverFatal
	}
}

// setRerouteToken stores the conn's current reroute token, replacing any prior
// one (a successful takeover mints a fresh token bound to the new iteration).
func (conn *edgeConnXgress) setRerouteToken(token string) {
	conn.rerouteToken.Store(&token)
}

// getRerouteToken returns the conn's current reroute token, or empty if none.
func (conn *edgeConnXgress) getRerouteToken() string {
	if p := conn.rerouteToken.Load(); p != nil {
		return *p
	}
	return ""
}
