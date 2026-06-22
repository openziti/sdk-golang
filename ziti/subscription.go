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

package ziti

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/pb/edge_client_pb"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/openziti/sdk-golang/v2/ziti/edge/posture"
	"google.golang.org/protobuf/proto"
)

// routerSubscriptionIdleTimeout is how long a subscribed edge router may go without carrying a dial
// or bind before the idle sweep unsubscribes it. The last remaining subscription is always retained
// so the SDK never loses its push view.
const routerSubscriptionIdleTimeout = 5 * time.Minute

// SubscribeToServiceUpdatesFromRouter opts in to router-pushed service and posture updates. It
// subscribes one capable edge router to bootstrap the push view; thereafter subscription follows
// traffic — each router a dial or bind uses is subscribed — and idle routers are unsubscribed after
// routerSubscriptionIdleTimeout, always keeping at least one. Subscribed routers push
// ServiceChangeSet and PostureStateChange messages, which are applied to the service cache and
// emitted as EventServiceAdded/EventServiceChanged/EventServiceRemoved.
//
// While at least one router push subscription is active, controller-side service polling is
// suspended; call UnsubscribeFromServiceUpdatesFromRouter to resume polling. Routers that do not
// advertise the ServiceSubscriptions capability are skipped; if none support it, polling continues
// unchanged.
func (context *ContextImpl) SubscribeToServiceUpdatesFromRouter() error {
	context.subscriptionLock.Lock()
	if context.subscriptionCoordinator.Load() == nil {
		context.subscriptionCoordinator.Store(newSubscriptionCoordinator(context))
	}
	if context.subscribedRouters == nil {
		context.subscribedRouters = map[string]struct{}{}
	}
	context.subscriptionLock.Unlock()

	// Record the opt-in; the reconcile loop owns connecting/subscribing capable routers and keeps
	// the subscription alive as routers come and go. Each capable router is asked for a full
	// snapshot.
	context.pushSubscriptionDesired.Store(true)
	context.reconcilePushSubscription()
	return nil
}

// IsPushSubscriptionActive reports whether the SDK is currently relying on router-pushed service
// updates (true) versus controller polling (false). Exposed for tests to assert the push/poll
// transitions as capable routers come and go.
func (context *ContextImpl) IsPushSubscriptionActive() bool {
	return context.pushSubscriptionActive.Load()
}

// GetLastPostureSeq returns the seq of the most recent PostureStateChange applied on the app-view
// router (the highest-index subscribed router), or 0 if none. Gray-box accessor for tests.
func (context *ContextImpl) GetLastPostureSeq() uint64 {
	c := context.getSubscriptionCoordinator()
	if c == nil {
		return 0
	}
	return c.appViewPostureSeq()
}

// GetPostureCheckPassing returns the last-known pass/fail state for a posture check by id on the
// app-view router. The second return is false if no state for that check has been received.
// Gray-box accessor for tests.
func (context *ContextImpl) GetPostureCheckPassing(checkId string) (isPassing bool, found bool) {
	c := context.getSubscriptionCoordinator()
	if c == nil {
		return false, false
	}
	return c.appViewCheckPassing(checkId)
}

// GetPosturePolicyPassing returns the last-known pass/fail state for a service policy by id on the
// app-view router. The second return is false if no state for that policy has been received.
// Gray-box accessor for tests.
func (context *ContextImpl) GetPosturePolicyPassing(policyId string) (isPassing bool, found bool) {
	c := context.getSubscriptionCoordinator()
	if c == nil {
		return false, false
	}
	return c.appViewPolicyPassing(policyId)
}

// getSubscriptionCoordinator reads the coordinator lock-free. It MUST NOT take subscriptionLock:
// posture evaluation calls this while subscription paths that hold subscriptionLock (reconcile ->
// connect -> initialize posture) re-enter evaluation on the same goroutine.
func (context *ContextImpl) getSubscriptionCoordinator() *subscriptionCoordinator {
	return context.subscriptionCoordinator.Load()
}

var _ posture.RouterQueryInfoProvider = (*ContextImpl)(nil)

// GetRouterPostureQueryInfo implements posture.RouterQueryInfoProvider: it returns the posture
// query info conn's pushed structural state requires for the identity's active dial and bind
// services. The bool is false when conn holds no per-router state (not push-subscribed, or no
// snapshot applied yet); the posture cache then falls back to the globally-derived query info.
func (context *ContextImpl) GetRouterPostureQueryInfo(conn edge.RouterConn) (*posture.QueryInfo, bool) {
	c := context.getSubscriptionCoordinator()
	if c == nil {
		return nil, false
	}
	return c.routerQueryInfo(conn)
}

// reconcilePushSubscription maintains the push-subscription floor: it prunes subscriptions whose
// connection has gone away and, if push is opted in and none remain, subscribes one capable router
// to bootstrap (and re-establish, after a capable router returns) the SDK's push view. Beyond the
// floor, subscription follows traffic (see ensureRouterSubscribed) and is trimmed by the idle sweep
// (see sweepIdleSubscriptions). Safe to call repeatedly; it is the reconnect heartbeat.
//
// Network I/O (the controller list, router dials, subscribe sends) happens OUTSIDE
// subscriptionLock: connection-close handling and every dial contend on that lock, so holding it
// across a slow controller call or a dead-router dial would stall them for the connect timeout.
func (context *ContextImpl) reconcilePushSubscription() {
	if !context.pushSubscriptionDesired.Load() {
		return
	}

	coordinator := context.subscriptionCoordinator.Load()
	if coordinator == nil {
		return
	}

	context.subscriptionLock.Lock()
	if context.subscribedRouters == nil {
		context.subscribedRouters = map[string]struct{}{}
	}

	// Prune subscriptions whose connection has gone away or is no longer capable.
	for addr := range context.subscribedRouters {
		conn, found := context.routerConnections.Get(addr)
		if !found || conn.IsClosed() || !conn.IsRouterCapable(edge.RouterCapabilityServiceSubscriptions) {
			delete(context.subscribedRouters, addr)
		}
	}
	needFloor := len(context.subscribedRouters) == 0 && len(context.subscribingRouters) == 0
	context.subscriptionLock.Unlock()

	// Maintain the floor: keep at least one subscribed router.
	if needFloor {
		ers, err := context.CtrlClt.GetAvailableERs()
		if err != nil {
			pfxlog.Logger().WithError(err).Debug("reconcilePushSubscription: could not list edge routers")
		}
		context.subscribeOne(coordinator, ers)
	}

	context.subscriptionLock.Lock()
	subscribed := len(context.subscribedRouters)
	context.subscriptionLock.Unlock()
	context.setPushSubscriptionActive(subscribed > 0)
}

// setPushSubscriptionActive records push/poll mode changes, logging each transition once.
func (context *ContextImpl) setPushSubscriptionActive(active bool) {
	if active {
		if !context.pushSubscriptionActive.Swap(true) {
			pfxlog.Logger().Info("router push subscription active; controller service polling paused")
		}
	} else if context.pushSubscriptionActive.Swap(false) {
		pfxlog.Logger().Info("router push subscription inactive; resuming controller service polling")
	}
}

// reserveSubscription marks addr as having a subscribe in flight, returning false when it is
// already subscribed or reserved, so concurrent subscribers skip it.
func (context *ContextImpl) reserveSubscription(addr string) bool {
	context.subscriptionLock.Lock()
	defer context.subscriptionLock.Unlock()
	if _, ok := context.subscribedRouters[addr]; ok {
		return false
	}
	if _, ok := context.subscribingRouters[addr]; ok {
		return false
	}
	if context.subscribingRouters == nil {
		context.subscribingRouters = map[string]struct{}{}
	}
	context.subscribingRouters[addr] = struct{}{}
	return true
}

// releaseSubscription clears addr's in-flight reservation after a failed subscribe attempt.
func (context *ContextImpl) releaseSubscription(addr string) {
	context.subscriptionLock.Lock()
	defer context.subscriptionLock.Unlock()
	delete(context.subscribingRouters, addr)
}

// commitSubscription clears addr's in-flight reservation and records it as subscribed. It refuses
// (returning false) when an unsubscribe raced the in-flight subscribe — the push opt-in was
// cleared, or the coordinator no longer tracks conn (UnsubscribeFromServiceUpdatesFromRouter
// clears both; a fast unsubscribe/resubscribe flips desired back on but leaves conn untracked).
// Committing anyway would count a router whose pushes are dropped as untracked toward the
// push-active state, pausing polling with no live push view. The caller must undo the router-side
// subscription (send an unsubscribe, drop coordinator state).
func (context *ContextImpl) commitSubscription(addr string, conn edge.RouterConn, coordinator *subscriptionCoordinator) bool {
	context.subscriptionLock.Lock()
	defer context.subscriptionLock.Unlock()
	delete(context.subscribingRouters, addr)
	if !context.pushSubscriptionDesired.Load() || !coordinator.isTracked(conn) {
		return false
	}
	if context.subscribedRouters == nil {
		context.subscribedRouters = map[string]struct{}{}
	}
	context.subscribedRouters[addr] = struct{}{}
	return true
}

// subscribeOne subscribes the first reachable, capable edge router from ers to satisfy the
// >=1 subscription floor, returning after the first success. Dials and sends happen outside
// subscriptionLock; the target address is reserved so concurrent subscribers skip it.
func (context *ContextImpl) subscribeOne(coordinator *subscriptionCoordinator, ers []*rest_model.CurrentIdentityEdgeRouterDetail) {
	for _, er := range ers {
		if er.Name == nil || !routerAdvertisesServiceSubscriptions(er) {
			continue
		}
		for _, addr := range er.SupportedProtocols {
			if !context.options.isEdgeRouterUrlAccepted(addr) {
				continue
			}
			addr = strings.Replace(addr, "//", "", 1)
			if !context.reserveSubscription(addr) {
				// Already subscribed or another path is subscribing this router: floor satisfied.
				return
			}
			result := context.connectEdgeRouter(*er.Name, addr)
			if result.err != nil || result.routerConnection == nil {
				context.releaseSubscription(addr)
				continue
			}
			conn := result.routerConnection
			// Ground truth: only rely on push for a connection that confirms the capability on the wire.
			if !conn.IsRouterCapable(edge.RouterCapabilityServiceSubscriptions) {
				context.releaseSubscription(addr)
				continue
			}
			coordinator.trackRouter(conn)
			conn.SetServiceSubscriptionHandler(coordinator)
			if err := conn.SubscribeToServiceUpdates(-1); err != nil {
				pfxlog.Logger().WithError(err).Errorf("subscribeOne: subscribe to [%s] failed", addr)
				coordinator.removeRouter(conn)
				context.releaseSubscription(addr)
				continue
			}
			if !context.commitSubscription(addr, conn, coordinator) {
				context.undoOrphanedSubscription(addr, conn, coordinator)
				return
			}
			pfxlog.Logger().WithField("routerAddr", addr).Debug("subscribed to service updates on router")
			coordinator.requestViewChange(conn)
			return
		}
	}
}

// ensureRouterSubscribed is the subscribe-follows-traffic hook: when a dial or bind uses conn, it
// refreshes the router's idle timer and, if push is opted in and the router is capable, subscribes
// it when not already subscribed. conn is already connected, so no dial is performed here.
func (context *ContextImpl) ensureRouterSubscribed(conn edge.RouterConn) {
	if conn == nil || !context.pushSubscriptionDesired.Load() {
		return
	}

	coordinator := context.subscriptionCoordinator.Load()
	if coordinator == nil {
		return
	}

	coordinator.markActive(conn)
	if conn.IsClosed() || !conn.IsRouterCapable(edge.RouterCapabilityServiceSubscriptions) {
		return
	}

	addr := conn.GetRouterAddr()
	if !context.reserveSubscription(addr) {
		return
	}

	coordinator.trackRouter(conn)
	conn.SetServiceSubscriptionHandler(coordinator)
	if err := conn.SubscribeToServiceUpdates(-1); err != nil {
		pfxlog.Logger().WithError(err).Errorf("ensureRouterSubscribed: subscribe to [%s] failed", addr)
		coordinator.removeRouter(conn)
		context.releaseSubscription(addr)
		return
	}

	if !context.commitSubscription(addr, conn, coordinator) {
		context.undoOrphanedSubscription(addr, conn, coordinator)
		return
	}
	pfxlog.Logger().WithField("routerAddr", addr).Debug("subscribed to service updates on router")
	coordinator.requestViewChange(conn)
	context.setPushSubscriptionActive(true)
}

// undoOrphanedSubscription unwinds a router-side subscription whose commit was refused because an
// unsubscribe raced it: the subscribe message may have reached the router after the opt-out
// broadcast, leaving it pushing to a connection the coordinator no longer tracks.
func (context *ContextImpl) undoOrphanedSubscription(addr string, conn edge.RouterConn, coordinator *subscriptionCoordinator) {
	pfxlog.Logger().WithField("routerAddr", addr).
		Debug("unsubscribe raced an in-flight subscribe; undoing the orphaned router subscription")
	if err := conn.UnsubscribeFromServiceUpdates(); err != nil {
		pfxlog.Logger().WithError(err).Debugf("failed to unsubscribe orphaned router subscription [%s]", addr)
	}
	coordinator.removeRouter(conn)
}

// subscriptionsToDrop returns how many of idleCount idle subscriptions may be unsubscribed while
// always retaining at least one subscription among total.
func subscriptionsToDrop(idleCount, total int) int {
	drop := idleCount
	if total-drop < 1 {
		drop = total - 1
	}
	if drop < 0 {
		drop = 0
	}
	return drop
}

// sweepIdleSubscriptions unsubscribes push subscriptions on routers that have carried no dial or
// bind within routerSubscriptionIdleTimeout, always retaining at least one subscription.
func (context *ContextImpl) sweepIdleSubscriptions() {
	if !context.pushSubscriptionDesired.Load() {
		return
	}

	context.subscriptionLock.Lock()
	coordinator := context.subscriptionCoordinator.Load()
	if coordinator == nil {
		context.subscriptionLock.Unlock()
		return
	}
	cutoff := time.Now().Add(-routerSubscriptionIdleTimeout)

	type idleRouter struct {
		addr string
		conn edge.RouterConn
	}
	var idle []idleRouter
	for addr := range context.subscribedRouters {
		conn, found := context.routerConnections.Get(addr)
		if !found {
			continue
		}
		if last, ok := coordinator.idleSince(conn); ok && last.Before(cutoff) {
			idle = append(idle, idleRouter{addr: addr, conn: conn})
		}
	}

	// Never unsubscribe the last remaining subscription.
	idle = idle[:subscriptionsToDrop(len(idle), len(context.subscribedRouters))]
	for _, r := range idle {
		delete(context.subscribedRouters, r.addr)
	}
	context.subscriptionLock.Unlock()

	for _, r := range idle {
		if err := r.conn.UnsubscribeFromServiceUpdates(); err != nil {
			pfxlog.Logger().Debugf("sweepIdleSubscriptions: unsubscribe [%s] failed: %v", r.addr, err)
		}
		coordinator.removeRouter(r.conn)
		pfxlog.Logger().WithField("routerAddr", r.addr).Debug("unsubscribed from service updates on idle router")
	}
}

// routerAdvertisesServiceSubscriptions reports whether an edge router from the controller's list
// should be treated as a push candidate. Empty capabilities means the controller/edge-api is too
// old to populate the field ("unknown"); in that case the SDK optimistically tries the router and
// lets the live connection header be the ground truth. A non-empty list lacking the capability
// means the router is known-incapable and is skipped.
func routerAdvertisesServiceSubscriptions(er *rest_model.CurrentIdentityEdgeRouterDetail) bool {
	if len(er.Capabilities) == 0 {
		return true
	}
	for _, capability := range er.Capabilities {
		if capability == string(rest_model.RouterCapabilitiesSERVICESUBSCRIPTIONS) {
			return true
		}
	}
	return false
}

// UnsubscribeFromServiceUpdatesFromRouter clears the push opt-in, tells connected routers to stop
// pushing, and re-enables the controller polling loop.
func (context *ContextImpl) UnsubscribeFromServiceUpdatesFromRouter() {
	context.pushSubscriptionDesired.Store(false)

	for tpl := range context.routerConnections.IterBuffered() {
		conn := tpl.Val
		if err := conn.UnsubscribeFromServiceUpdates(); err != nil {
			pfxlog.Logger().Debugf("UnsubscribeFromServiceUpdatesFromRouter: send to [%s] failed: %v", conn.GetRouterAddr(), err)
		}
	}

	context.subscriptionLock.Lock()
	context.subscribedRouters = map[string]struct{}{}
	if coordinator := context.subscriptionCoordinator.Load(); coordinator != nil {
		coordinator.clear()
	}
	context.subscriptionLock.Unlock()

	wasActive := context.pushSubscriptionActive.Load()
	context.setPushSubscriptionActive(false)
	if wasActive {
		// Subscription was active; fall back to polling immediately.
		if err := context.refreshServices(true, false); err != nil {
			pfxlog.Logger().WithError(err).Error("failed to refresh services after push unsubscribe")
		}
	}
}

// subscriptionCoordinator receives ServiceChangeSet and PostureStateChange messages from every
// subscribed edge router and maintains independent per-router state. Routers advance through RDM
// indices on their own and, during a partition, can sit on different indices, so their structural
// and posture state must not be shared. The application-facing service cache is materialized from
// the router at the highest structural index seen (see materializeLocked).
type subscriptionCoordinator struct {
	mu      sync.Mutex
	ctx     *ContextImpl
	routers map[edge.RouterConn]*routerSubscription

	// materializeSignal coalesces app-view rebuild requests for the materialize worker (see
	// requestMaterialize). Buffered with capacity 1: a pending signal already covers any state
	// change made before the worker runs.
	materializeSignal chan struct{}

	// viewChangePending accumulates routers whose view changed for the view-event worker (see
	// requestViewChange); viewChangeSignal (capacity 1) wakes it. Views render fresh at emit
	// time with no locks held.
	viewChangeMu      sync.Mutex
	viewChangePending map[edge.RouterConn]struct{}
	viewChangeSignal  chan struct{}
}

// routerSubscription is the independent structural + posture state for one subscribed router.
type routerSubscription struct {
	// structuralIndex is the RDM index of the last applied ServiceChangeSet; -1 before any snapshot.
	structuralIndex int64

	// lastActivity is when a dial or bind last used this router; the idle sweep unsubscribes routers
	// that go quiet for routerSubscriptionIdleTimeout.
	lastActivity time.Time

	// Structural cache accumulated from this router's ServiceChangeSet stream, so incremental
	// updates can reference policies/checks by id without resending full definitions.
	policiesById      map[string]*edge_client_pb.PolicyDef
	postureChecksById map[string]*edge_client_pb.PostureCheckDef
	servicesById      map[string]*edge_client_pb.ServiceDef

	// Posture stream state for this connection. seq is per-connection and starts at 1.
	// postureResyncPending is set after a seq gap while a ResyncPostureState full re-send is in
	// flight; the next state accepted is authoritative at whatever seq it carries.
	havePosture          bool
	postureSeq           uint64
	postureResyncPending bool
	checkStates          map[string]bool
	policyStates         map[string]bool
}

func newRouterSubscription() *routerSubscription {
	return &routerSubscription{
		structuralIndex:   -1,
		policiesById:      map[string]*edge_client_pb.PolicyDef{},
		postureChecksById: map[string]*edge_client_pb.PostureCheckDef{},
		servicesById:      map[string]*edge_client_pb.ServiceDef{},
		checkStates:       map[string]bool{},
		policyStates:      map[string]bool{},
	}
}

func (sub *routerSubscription) resetStructural() {
	sub.policiesById = map[string]*edge_client_pb.PolicyDef{}
	sub.postureChecksById = map[string]*edge_client_pb.PostureCheckDef{}
	sub.servicesById = map[string]*edge_client_pb.ServiceDef{}
}

// pruneStateOverlay drops posture pass/fail entries no longer reachable from the structural
// cache (service -> policy -> check references): removed structure's state is stale, and
// surfacing it (e.g. through RouterView) would misreport posture. Runs after a full
// ServiceChangeSet has applied — never entry-by-entry, so an envelope that removes and re-adds a
// reference does not transiently prune live state. Caller must hold the coordinator lock.
func (sub *routerSubscription) pruneStateOverlay() {
	referencedPolicies := map[string]struct{}{}
	for _, svcDef := range sub.servicesById {
		for _, policyId := range svcDef.PolicyIds {
			referencedPolicies[policyId] = struct{}{}
		}
	}
	referencedChecks := map[string]struct{}{}
	for policyId := range referencedPolicies {
		if policy, ok := sub.policiesById[policyId]; ok {
			for _, checkId := range policy.PostureCheckIds {
				referencedChecks[checkId] = struct{}{}
			}
		}
	}
	for policyId := range sub.policyStates {
		if _, ok := referencedPolicies[policyId]; !ok {
			delete(sub.policyStates, policyId)
		}
	}
	for checkId := range sub.checkStates {
		if _, ok := referencedChecks[checkId]; !ok {
			delete(sub.checkStates, checkId)
		}
	}
}

var _ edge.ServiceSubscriptionHandler = (*subscriptionCoordinator)(nil)

func newSubscriptionCoordinator(ctx *ContextImpl) *subscriptionCoordinator {
	c := &subscriptionCoordinator{
		ctx:               ctx,
		routers:           map[edge.RouterConn]*routerSubscription{},
		materializeSignal: make(chan struct{}, 1),
		viewChangePending: map[edge.RouterConn]struct{}{},
		viewChangeSignal:  make(chan struct{}, 1),
	}
	if ctx != nil {
		go c.materializeLoop(ctx.closeNotify)
		go c.viewChangeLoop(ctx.closeNotify)
	}
	return c
}

// requestMaterialize schedules an app-view rebuild on the materialize worker. Callers may hold
// coordinator or subscription locks; the rebuild itself runs with none of them held, because it
// emits service events whose listeners may re-enter the SDK (dial, subscribe, evaluate posture) —
// firing those under a lock deadlocks.
func (c *subscriptionCoordinator) requestMaterialize() {
	select {
	case c.materializeSignal <- struct{}{}:
	default: // a rebuild is already pending and will observe this change's state
	}
}

// materializeLoop drains rebuild requests until the owning context closes.
func (c *subscriptionCoordinator) materializeLoop(closeNotify <-chan struct{}) {
	for {
		select {
		case <-c.materializeSignal:
			c.materialize()
		case <-closeNotify:
			return
		}
	}
}

// trackRouter ensures per-router state exists for conn before its stream begins, stamping it active.
func (c *subscriptionCoordinator) trackRouter(conn edge.RouterConn) {
	c.mu.Lock()
	if _, ok := c.routers[conn]; !ok {
		sub := newRouterSubscription()
		sub.lastActivity = time.Now()
		c.routers[conn] = sub
	}
	c.mu.Unlock()

	c.requestViewChange(conn)
}

// markActive refreshes a router's idle timer when a dial or bind uses it. No-op if untracked.
func (c *subscriptionCoordinator) markActive(conn edge.RouterConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sub, ok := c.routers[conn]; ok {
		sub.lastActivity = time.Now()
	}
}

// isTracked reports whether conn still has per-router state. A subscribe in flight when the app
// unsubscribes loses its tracking (clear or removeRouter), so its completion must not commit the
// router as subscribed — the coordinator would drop its pushes as untracked.
func (c *subscriptionCoordinator) isTracked(conn edge.RouterConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.routers[conn]
	return ok
}

// idleSince returns when a tracked router was last active. The bool is false if untracked.
func (c *subscriptionCoordinator) idleSince(conn edge.RouterConn) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sub, ok := c.routers[conn]; ok {
		return sub.lastActivity, true
	}
	return time.Time{}, false
}

// removeRouter drops a router's state (on disconnect or subscribe failure) and re-materializes the
// app view from whatever router now holds the highest index.
func (c *subscriptionCoordinator) removeRouter(conn edge.RouterConn) {
	c.mu.Lock()
	if _, ok := c.routers[conn]; !ok {
		c.mu.Unlock()
		return
	}
	delete(c.routers, conn)
	c.mu.Unlock()

	c.requestMaterialize()
	c.requestViewChange(conn)
}

// clear drops all per-router state (on unsubscribe).
func (c *subscriptionCoordinator) clear() {
	c.mu.Lock()
	conns := make([]edge.RouterConn, 0, len(c.routers))
	for conn := range c.routers {
		conns = append(conns, conn)
	}
	c.routers = map[edge.RouterConn]*routerSubscription{}
	c.mu.Unlock()

	for _, conn := range conns {
		c.requestViewChange(conn)
	}
}

func (c *subscriptionCoordinator) HandleServiceChangeSet(conn edge.RouterConn, msg *channel.Message) {
	cs := &edge_client_pb.ServiceChangeSet{}
	if err := proto.Unmarshal(msg.Body, cs); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to unmarshal ServiceChangeSet")
		return
	}

	c.mu.Lock()
	sub, ok := c.routers[conn]
	if !ok {
		// Not tracked: the app unsubscribed or the idle sweep dropped this router, and this push
		// was already in flight. Recreating state here would start the router at index -1, read
		// the next incremental as a gap, and resubscribe against the opt-out — so drop instead.
		c.mu.Unlock()
		pfxlog.Logger().Debugf("dropping ServiceChangeSet index %d from untracked router [%s]", cs.Index, conn.GetRouterName())
		return
	}

	// An incremental envelope at or below the committed index is a duplicate/stale delivery: drop
	// it without treating it as a gap and without regressing the committed index. Full snapshots
	// (previousIndex == -1) are authoritative resets and always apply, even at the same index.
	if cs.PreviousIndex != -1 && sub.structuralIndex >= 0 && cs.Index <= sub.structuralIndex {
		committed := sub.structuralIndex
		c.mu.Unlock()
		pfxlog.Logger().Debugf("dropping stale ServiceChangeSet from router [%s]: index %d at or below committed %d",
			conn.GetRouterName(), cs.Index, committed)
		return
	}

	// Per-router gap detection: an incremental changeset must chain from this router's current
	// index. A full snapshot (previousIndex == -1) always applies and resets the router's cache.
	if cs.PreviousIndex != -1 && cs.PreviousIndex != sub.structuralIndex {
		c.mu.Unlock()
		pfxlog.Logger().Debugf("service changeset gap on router [%s]: have index %d, got previousIndex %d (index %d); resubscribing for a full snapshot",
			conn.GetRouterName(), sub.structuralIndex, cs.PreviousIndex, cs.Index)
		if err := conn.SubscribeToServiceUpdates(-1); err != nil {
			pfxlog.Logger().WithError(err).Errorf("failed to resubscribe router [%s] after changeset gap", conn.GetRouterName())
		}
		return
	}

	if cs.PreviousIndex == -1 {
		sub.resetStructural()
	}
	for _, p := range cs.Policies {
		if p.Op == edge_client_pb.Op_Removed {
			delete(sub.policiesById, p.Id)
		} else {
			sub.policiesById[p.Id] = p
		}
	}
	for _, pc := range cs.PostureChecks {
		if pc.Op == edge_client_pb.Op_Removed {
			delete(sub.postureChecksById, pc.Id)
		} else {
			sub.postureChecksById[pc.Id] = pc
		}
	}
	for _, svcDef := range cs.Services {
		switch svcDef.Op {
		case edge_client_pb.Op_Removed:
			delete(sub.servicesById, svcDef.Id)
		case edge_client_pb.Op_Added, edge_client_pb.Op_Updated:
			sub.servicesById[svcDef.Id] = svcDef
		}
	}
	sub.structuralIndex = cs.Index
	sub.pruneStateOverlay()
	c.mu.Unlock()

	c.requestMaterialize()
	c.requestViewChange(conn)
}

func (c *subscriptionCoordinator) HandlePostureStateChange(conn edge.RouterConn, msg *channel.Message) {
	ps := &edge_client_pb.PostureStateChange{}
	if err := proto.Unmarshal(msg.Body, ps); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to unmarshal PostureStateChange")
		return
	}

	c.mu.Lock()
	sub, ok := c.routers[conn]
	if !ok {
		// Not tracked (unsubscribed or idle-swept, push already in flight): drop rather than
		// recreating state — see HandleServiceChangeSet.
		c.mu.Unlock()
		pfxlog.Logger().Debugf("dropping PostureStateChange seq %d (structuralIndex %d) from untracked router [%s]",
			ps.Seq, ps.StructuralIndex, conn.GetRouterName())
		return
	}

	// Per-router seq handling: seq is a per-connection monotonic counter. A stale seq is a
	// duplicate and drops; a gap means we missed a posture update, and since posture state is
	// unindexed the recovery is full replacement — request a ResyncPostureState and accept the
	// resulting full state as authoritative at whatever seq it carries. Resubscribing would
	// needlessly reset the structural stream too.
	if sub.havePosture && !sub.postureResyncPending {
		if ps.Seq <= sub.postureSeq {
			applied := sub.postureSeq
			c.mu.Unlock()
			pfxlog.Logger().Debugf("dropping stale PostureStateChange from router [%s]: seq %d (structuralIndex %d) at or below applied seq %d",
				conn.GetRouterName(), ps.Seq, ps.StructuralIndex, applied)
			return
		}
		if ps.Seq != sub.postureSeq+1 {
			sub.postureResyncPending = true
			c.mu.Unlock()
			pfxlog.Logger().Debugf("posture state seq gap on router [%s]: expected %d got %d (structuralIndex %d); requesting posture resync",
				conn.GetRouterName(), sub.postureSeq+1, ps.Seq, ps.StructuralIndex)
			if err := conn.ResyncPostureState(); err != nil {
				pfxlog.Logger().WithError(err).Errorf("failed to request posture resync from router [%s]", conn.GetRouterName())
			}
			return
		}
	}
	sub.havePosture = true
	sub.postureSeq = ps.Seq
	sub.postureResyncPending = false

	// Full-state replacement: rebuild this router's per-check and per-policy pass/fail maps.
	checkStates := make(map[string]bool, len(ps.CheckStates))
	for _, checkState := range ps.CheckStates {
		checkStates[checkState.CheckId] = checkState.IsPassing
	}
	policyStates := make(map[string]bool, len(ps.PolicyStates))
	for _, policyState := range ps.PolicyStates {
		policyStates[policyState.PolicyId] = policyState.IsPassing
	}
	sub.checkStates = checkStates
	sub.policyStates = policyStates
	c.mu.Unlock()

	c.requestViewChange(conn)
}

// appViewRouterLocked returns the subscribed router with the highest structural index — the one that
// backs the application-facing service cache. Ties and unsubscribed-yet-tracked routers (index -1)
// resolve to the highest; nil when no router has state. Caller must hold c.mu.
func (c *subscriptionCoordinator) appViewRouterLocked() *routerSubscription {
	var best *routerSubscription
	for _, sub := range c.routers {
		if best == nil || sub.structuralIndex > best.structuralIndex {
			best = sub
		}
	}
	return best
}

// materialize rebuilds the application-facing service cache from the highest-index router,
// emitting add/update events for its services and removal events for services no longer present.
// It computes the desired view under the coordinator lock, then applies it and emits events with
// no locks held (see requestMaterialize). Runs only on the materialize worker, which serializes
// rebuilds.
func (c *subscriptionCoordinator) materialize() {
	c.mu.Lock()
	best := c.appViewRouterLocked()
	if best == nil || best.structuralIndex < 0 {
		c.mu.Unlock()
		return
	}

	desired := make(map[string]*rest_model.ServiceDetail, len(best.servicesById))
	for _, def := range best.servicesById {
		svc := c.buildServiceDetail(best, def)
		desired[*svc.Name] = svc
	}
	c.mu.Unlock()

	var toRemove []*rest_model.ServiceDetail
	c.ctx.services.IterCb(func(name string, svc *rest_model.ServiceDetail) {
		if _, ok := desired[name]; !ok {
			toRemove = append(toRemove, svc)
		}
	})
	for _, svc := range toRemove {
		c.ctx.removeService(*svc.Name, svc)
	}
	for _, svc := range desired {
		// A pushed ServiceDef carries only the fields the router knows; a service already cached
		// from controller polling also has metadata push does not carry (tags, role attributes,
		// timestamps, max idle time, terminator strategy). Merge the pushed fields into the cached
		// detail rather than replacing it, so consumers see no field loss and no spurious changed
		// events on the poll-to-push handoff.
		if existing, ok := c.ctx.services.Get(*svc.Name); ok {
			svc = mergePushedServiceDetail(existing, svc)
		}
		c.ctx.processServiceAddOrUpdated(svc)
	}
}

// mergePushedServiceDetail overlays the fields a router push is authoritative for onto a copy of
// the polled service detail, preserving everything push does not carry.
func mergePushedServiceDetail(existing, pushed *rest_model.ServiceDetail) *rest_model.ServiceDetail {
	merged := *existing
	merged.ID = pushed.ID
	merged.Name = pushed.Name
	merged.EncryptionRequired = pushed.EncryptionRequired
	merged.Permissions = pushed.Permissions
	merged.Configs = pushed.Configs
	merged.Config = pushed.Config
	merged.PostureQueries = pushed.PostureQueries
	return &merged
}

// routerQueryInfo builds the posture requirements for one subscribed router from that router's
// pushed structural cache, restricted to the services the application actively dials or binds —
// the per-router analogue of the global active-services-only posture collection. The bool is false
// when the router is untracked or has no applied snapshot yet.
func (c *subscriptionCoordinator) routerQueryInfo(conn edge.RouterConn) (*posture.QueryInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, false
	}
	sub, ok := c.routers[conn]
	if !ok || sub.structuralIndex < 0 {
		return nil, false
	}

	// Only the posture queries matter here; building full service details would re-parse every
	// pushed config body on each evaluation pass for nothing (and log per malformed config).
	var dialServices []*rest_model.ServiceDetail
	c.ctx.activeDials.IterCb(func(id string, _ *rest_model.ServiceDetail) {
		if def, present := sub.servicesById[id]; present {
			dialServices = append(dialServices, &rest_model.ServiceDetail{PostureQueries: buildPostureQueries(sub, def)})
		}
	})
	var bindServices []*rest_model.ServiceDetail
	c.ctx.activeBinds.IterCb(func(id string, _ *rest_model.ServiceDetail) {
		if def, present := sub.servicesById[id]; present {
			bindServices = append(bindServices, &rest_model.ServiceDetail{PostureQueries: buildPostureQueries(sub, def)})
		}
	})

	return posture.GetQueryInfo(dialServices, bindServices), true
}

func (c *subscriptionCoordinator) appViewPostureSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if best := c.appViewRouterLocked(); best != nil {
		return best.postureSeq
	}
	return 0
}

func (c *subscriptionCoordinator) appViewCheckPassing(checkId string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if best := c.appViewRouterLocked(); best != nil {
		isPassing, found := best.checkStates[checkId]
		return isPassing, found
	}
	return false, false
}

func (c *subscriptionCoordinator) appViewPolicyPassing(policyId string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if best := c.appViewRouterLocked(); best != nil {
		isPassing, found := best.policyStates[policyId]
		return isPassing, found
	}
	return false, false
}

// buildServiceDetail converts a router-pushed ServiceDef into a rest_model.ServiceDetail using the
// given router's structural cache to resolve permissions, posture queries, and config bodies.
func (c *subscriptionCoordinator) buildServiceDetail(sub *routerSubscription, def *edge_client_pb.ServiceDef) *rest_model.ServiceDetail {
	id := def.Id
	name := def.Name
	encRequired := def.EncryptionRequired

	svc := &rest_model.ServiceDetail{
		BaseEntity: rest_model.BaseEntity{
			ID: &id,
		},
		Name:               &name,
		EncryptionRequired: &encRequired,
		Configs:            def.Configs,
		Config:             map[string]map[string]interface{}{},
	}

	// Permissions are emitted in a canonical dial-then-bind order regardless of policy iteration
	// order, so a detail built from push never differs from an equivalent polled detail (and from
	// itself across rebuilds) by ordering alone.
	dialAllowed, bindAllowed := false, false
	for _, policyId := range def.PolicyIds {
		policy, ok := sub.policiesById[policyId]
		if !ok {
			continue
		}
		switch policy.Type {
		case edge_client_pb.PolicyType_Dial:
			dialAllowed = true
		case edge_client_pb.PolicyType_Bind:
			bindAllowed = true
		}
	}
	if dialAllowed {
		svc.Permissions = append(svc.Permissions, rest_model.DialBindDial)
	}
	if bindAllowed {
		svc.Permissions = append(svc.Permissions, rest_model.DialBindBind)
	}

	// Resolve the posture checks each granting policy carries so the SDK posture cache knows which
	// posture data to collect and submit for this service. Without this, pushed services never
	// drive posture submissions.
	svc.PostureQueries = buildPostureQueries(sub, def)

	// Populate the parsed config map from the identity-resolved config bodies the router pushed,
	// keyed by config type name. This is the config content the SDK would otherwise fetch from
	// the controller.
	for _, cd := range def.ConfigData {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(cd.DataJson), &data); err != nil {
			pfxlog.Logger().WithError(err).Errorf("failed to parse config data for service %s type %s", name, cd.TypeName)
			continue
		}
		svc.Config[cd.TypeName] = data
	}

	return svc
}

// buildPostureQueries converts a router's policy/posture-check cache into the ServiceDetail
// PostureQueries the SDK posture cache reads to decide which posture data to collect and submit. One
// PostureQueries set is produced per referencing policy that carries posture checks. Pass/fail state
// is not set here; it arrives separately on the posture-state stream.
func buildPostureQueries(sub *routerSubscription, def *edge_client_pb.ServiceDef) []*rest_model.PostureQueries {
	var result []*rest_model.PostureQueries
	for _, policyId := range def.PolicyIds {
		policy, ok := sub.policiesById[policyId]
		if !ok || len(policy.PostureCheckIds) == 0 {
			continue
		}

		var queries []*rest_model.PostureQuery
		for _, checkId := range policy.PostureCheckIds {
			if check, ok := sub.postureChecksById[checkId]; ok {
				queries = append(queries, buildPostureQuery(check))
			}
		}
		if len(queries) == 0 {
			continue
		}

		id := policy.Id
		result = append(result, &rest_model.PostureQueries{
			PolicyID:       &id,
			PolicyType:     policyDialBind(policy.Type),
			PostureQueries: queries,
		})
	}
	return result
}

// buildPostureQuery converts one router-pushed PostureCheckDef into a rest_model.PostureQuery,
// populating the fields the SDK posture cache consumes: the query type, id, process paths for
// process checks, and the MFA timeout the cache reads to schedule TOTP refresh.
func buildPostureQuery(check *edge_client_pb.PostureCheckDef) *rest_model.PostureQuery {
	id := check.Id
	queryType := rest_model.PostureCheckType(check.Type)
	q := &rest_model.PostureQuery{
		BaseEntity: rest_model.BaseEntity{ID: &id},
		QueryType:  &queryType,
	}
	// TimeoutSeconds 0 means the router predates the field; leave Timeout unset rather than
	// implying an immediate timeout. -1 (no timeout) passes through as-is.
	if check.TimeoutSeconds != 0 {
		timeout := check.TimeoutSeconds
		q.Timeout = &timeout
	}
	for _, p := range check.Processes {
		q.Processes = append(q.Processes, &rest_model.PostureQueryProcess{
			OsType: rest_model.OsType(p.OsType),
			Path:   p.Path,
		})
	}
	return q
}

func policyDialBind(t edge_client_pb.PolicyType) rest_model.DialBind {
	if t == edge_client_pb.PolicyType_Bind {
		return rest_model.DialBindBind
	}
	return rest_model.DialBindDial
}
