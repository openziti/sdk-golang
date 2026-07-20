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
	"testing"
	"time"

	"github.com/kataras/go-events"
	"github.com/openziti/channel/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/pb/edge_client_pb"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// stubRouterConn records SubscribeToServiceUpdates and ResyncPostureState calls; all other
// RouterConn methods come from the embedded (nil) interface and panic if unexpectedly invoked,
// which keeps the stub honest.
type stubRouterConn struct {
	edge.RouterConn
	name             string
	capable          bool
	subscribeCalls   []int64
	resyncCalls      int
	unsubscribeCalls int
}

func (s *stubRouterConn) GetRouterName() string { return s.name }

func (s *stubRouterConn) GetRouterId() string { return s.name + ".id" }

func (s *stubRouterConn) GetRouterAddr() string { return s.name + ".addr" }

func (s *stubRouterConn) IsClosed() bool { return false }

func (s *stubRouterConn) IsRouterCapable(int) bool { return s.capable }

func (s *stubRouterConn) SubscribeToServiceUpdates(index int64) error {
	s.subscribeCalls = append(s.subscribeCalls, index)
	return nil
}

func (s *stubRouterConn) UnsubscribeFromServiceUpdates() error {
	s.unsubscribeCalls++
	return nil
}

func (s *stubRouterConn) ResyncPostureState() error {
	s.resyncCalls++
	return nil
}

// TestBuildServiceDetailPostureQueries verifies that a router-pushed service carries the posture
// queries of its granting policies, so the SDK posture cache can drive posture collection for
// push-delivered services.
func TestBuildServiceDetailPostureQueries(t *testing.T) {
	sub := newRouterSubscription()
	sub.policiesById = map[string]*edge_client_pb.PolicyDef{
		"dial-policy": {
			Id:              "dial-policy",
			Type:            edge_client_pb.PolicyType_Dial,
			PostureCheckIds: []string{"mac-check", "proc-check", "mfa-check"},
		},
	}
	sub.postureChecksById = map[string]*edge_client_pb.PostureCheckDef{
		"mac-check": {
			Id:   "mac-check",
			Type: string(rest_model.PostureCheckTypeMAC),
		},
		"proc-check": {
			Id:   "proc-check",
			Type: string(rest_model.PostureCheckTypePROCESSMULTI),
			Processes: []*edge_client_pb.PostureCheckDef_Process{
				{OsType: "Windows", Path: "C:\\app.exe"},
			},
		},
		"mfa-check": {
			Id:             "mfa-check",
			Type:           string(rest_model.PostureCheckTypeMFA),
			TimeoutSeconds: 600,
		},
	}

	c := newSubscriptionCoordinator(nil)
	svc := c.buildServiceDetail(sub, &edge_client_pb.ServiceDef{
		Id:        "svc-1",
		Name:      "svc-1",
		PolicyIds: []string{"dial-policy"},
	})

	require.Len(t, svc.PostureQueries, 1, "one PostureQueries set per granting policy with checks")
	set := svc.PostureQueries[0]
	require.NotNil(t, set.PolicyID)
	require.Equal(t, "dial-policy", *set.PolicyID)
	require.Equal(t, rest_model.DialBindDial, set.PolicyType)
	require.Len(t, set.PostureQueries, 3)

	byId := map[string]*rest_model.PostureQuery{}
	for _, q := range set.PostureQueries {
		require.NotNil(t, q.ID)
		require.NotNil(t, q.QueryType)
		byId[*q.ID] = q
	}

	require.Equal(t, rest_model.PostureCheckTypeMAC, *byId["mac-check"].QueryType)

	proc := byId["proc-check"]
	require.Equal(t, rest_model.PostureCheckTypePROCESSMULTI, *proc.QueryType)
	require.Len(t, proc.Processes, 1)
	require.Equal(t, "C:\\app.exe", proc.Processes[0].Path)

	// The MFA timeout must ride the pushed query: the posture cache reads query.Timeout to
	// schedule TOTP refresh, exactly as it does for poll-delivered services.
	mfa := byId["mfa-check"]
	require.Equal(t, rest_model.PostureCheckTypeMFA, *mfa.QueryType)
	require.NotNil(t, mfa.Timeout, "pushed MFA query must carry the timeout")
	require.Equal(t, int64(600), *mfa.Timeout)
}

// TestServiceChangeSetGapTriggersResubscribe verifies that an incremental changeset that does not
// chain from a router's current structural index triggers a full (-1) resubscribe on that router,
// rather than being applied and silently corrupting state.
func TestServiceChangeSetGapTriggersResubscribe(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	// A freshly tracked router is at index -1; an incremental claiming previousIndex=5 is a gap.
	body, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{PreviousIndex: 5, Index: 6})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: body})

	require.Equal(t, []int64{-1}, conn.subscribeCalls, "structural gap should trigger a full resubscribe")
}

// TestPostureStateSeqGapTriggersResync verifies posture seq-gap recovery: a gap requests a full
// posture re-send (ResyncPostureState) rather than a structural resubscribe, the resulting full
// state is accepted as authoritative at whatever seq it carries (no infinite gap loop), and a
// stale/duplicate seq is dropped without being treated as a gap.
func TestPostureStateSeqGapTriggersResync(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	seq1, err := proto.Marshal(&edge_client_pb.PostureStateChange{Seq: 1})
	require.NoError(t, err)
	c.HandlePostureStateChange(conn, &channel.Message{Body: seq1})

	// A duplicate/stale delivery is dropped, not treated as a gap.
	c.HandlePostureStateChange(conn, &channel.Message{Body: seq1})
	require.Zero(t, conn.resyncCalls, "a stale seq is a duplicate, not a gap")

	// Jump from seq 1 to 3 — seq 2 was missed.
	seq3, err := proto.Marshal(&edge_client_pb.PostureStateChange{Seq: 3})
	require.NoError(t, err)
	c.HandlePostureStateChange(conn, &channel.Message{Body: seq3})

	require.Equal(t, 1, conn.resyncCalls, "a posture seq gap requests a full posture re-send")
	require.Empty(t, conn.subscribeCalls, "posture recovery must not reset the structural stream")

	// The requested full state arrives at the router's next seq (not the one after our last
	// applied seq); it must be accepted as authoritative, ending the gap.
	seq4, err := proto.Marshal(&edge_client_pb.PostureStateChange{
		Seq:         4,
		CheckStates: []*edge_client_pb.PostureStateChange_CheckState{{CheckId: "chk", IsPassing: true}},
	})
	require.NoError(t, err)
	c.HandlePostureStateChange(conn, &channel.Message{Body: seq4})

	require.Equal(t, 1, conn.resyncCalls, "the authoritative full state must not re-trigger a resync")
	c.mu.Lock()
	sub := c.routers[conn]
	seq := sub.postureSeq
	passing, found := sub.checkStates["chk"]
	c.mu.Unlock()
	require.Equal(t, uint64(4), seq, "the resync state's seq becomes the new baseline")
	require.True(t, found && passing, "the resync state must be applied")
}

// TestUntrackedConnPushIsDropped locks in that pushes from a router the coordinator no longer
// tracks (explicitly unsubscribed or idle-swept) are dropped: recreating state for them would put
// the recreated router at index -1, read the next incremental as a gap, and resubscribe the router
// against the opt-out — the zombie-resubscribe loop.
func TestUntrackedConnPushIsDropped(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"} // never tracked

	body, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{PreviousIndex: 5, Index: 6})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: body})

	require.Empty(t, conn.subscribeCalls, "an untracked conn's push must not trigger a resubscribe")
	c.mu.Lock()
	_, tracked := c.routers[conn]
	c.mu.Unlock()
	require.False(t, tracked, "no state may be recreated for an untracked conn")

	seq1, err := proto.Marshal(&edge_client_pb.PostureStateChange{Seq: 1})
	require.NoError(t, err)
	c.HandlePostureStateChange(conn, &channel.Message{Body: seq1})

	c.mu.Lock()
	_, tracked = c.routers[conn]
	c.mu.Unlock()
	require.False(t, tracked, "posture pushes from an untracked conn are dropped too")
}

// TestStaleServiceChangeSetIsDropped locks in the stale-envelope rule: an envelope whose index is
// at or below the router's committed index is a duplicate/stale delivery and is dropped without a
// resubscribe and without regressing the committed index.
func TestStaleServiceChangeSetIsDropped(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	c.mu.Lock()
	c.routers[conn].structuralIndex = 10
	c.mu.Unlock()

	body, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{PreviousIndex: 7, Index: 8})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: body})

	require.Empty(t, conn.subscribeCalls, "a stale envelope is not a gap; no resubscribe")
	c.mu.Lock()
	index := c.routers[conn].structuralIndex
	c.mu.Unlock()
	require.Equal(t, int64(10), index, "the committed index must not regress")
}

// TestAppViewRouterHighestIndex verifies the application-facing view is backed by the router at the
// highest structural index, so routers lagging during a partition do not drag the view backward.
func TestAppViewRouterHighestIndex(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	low := &stubRouterConn{name: "low"}
	high := &stubRouterConn{name: "high"}
	c.trackRouter(low)
	c.trackRouter(high)

	c.mu.Lock()
	c.routers[low].structuralIndex = 3
	c.routers[high].structuralIndex = 7
	best := c.appViewRouterLocked()
	c.mu.Unlock()

	require.Same(t, c.routers[high], best, "highest-index router should back the app view")
}

// TestMaterializeEmitsWithoutCoordinatorLock locks in that service events produced by a pushed
// changeset fire without the coordinator lock held: an event listener that re-enters the
// coordinator — as any listener-triggered dial does via markActive — must not deadlock.
func TestMaterializeEmitsWithoutCoordinatorLock(t *testing.T) {
	closeNotify := make(chan struct{})
	t.Cleanup(func() { close(closeNotify) })
	ctx := &ContextImpl{
		options:            &Options{},
		services:           cmap.New[*rest_model.ServiceDetail](),
		sessions:           cmap.New[*rest_model.SessionDetail](),
		serviceEdgeRouters: cmap.New[[]*rest_model.SessionEdgeRouter](),
		intercepts:         cmap.New[*edge.InterceptV1Config](),
		EventEmmiter:       events.New(),
		closeNotify:        closeNotify,
	}

	c := newSubscriptionCoordinator(ctx)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	delivered := make(chan struct{}, 1)
	ctx.AddListener(EventServiceAdded, func(args ...interface{}) {
		c.markActive(conn) // re-enters the coordinator exactly like a listener-triggered dial
		delivered <- struct{}{}
	})

	body, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
		Index:         1,
		PreviousIndex: -1,
		Services: []*edge_client_pb.ServiceDef{
			{Op: edge_client_pb.Op_Added, Id: "svc-1", Name: "svc-1"},
		},
	})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: body})

	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("service event never delivered: coordinator deadlocked on listener re-entry or the materialize worker is not running")
	}
}

// TestRouterQueryInfoDerivesFromRouterState locks in that a subscribed router's posture
// requirements come from that router's own pushed structural cache restricted to the actively
// dialed/bound services: checks for inactive services and services outside the router's view are
// excluded, and a router with no applied snapshot reports no per-router state.
func TestRouterQueryInfoDerivesFromRouterState(t *testing.T) {
	closeNotify := make(chan struct{})
	t.Cleanup(func() { close(closeNotify) })
	ctx := &ContextImpl{
		activeDials: cmap.New[*rest_model.ServiceDetail](),
		activeBinds: cmap.New[*rest_model.ServiceDetail](),
		closeNotify: closeNotify,
	}

	c := newSubscriptionCoordinator(ctx)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	_, ok := c.routerQueryInfo(conn)
	require.False(t, ok, "a router with no applied snapshot has no per-router state")

	c.mu.Lock()
	sub := c.routers[conn]
	sub.structuralIndex = 5
	sub.policiesById = map[string]*edge_client_pb.PolicyDef{
		"dial-policy": {
			Id:              "dial-policy",
			Type:            edge_client_pb.PolicyType_Dial,
			PostureCheckIds: []string{"mac-check", "proc-check"},
		},
	}
	sub.postureChecksById = map[string]*edge_client_pb.PostureCheckDef{
		"mac-check": {Id: "mac-check", Type: string(rest_model.PostureCheckTypeMAC)},
		"proc-check": {
			Id:   "proc-check",
			Type: string(rest_model.PostureCheckTypePROCESSMULTI),
			Processes: []*edge_client_pb.PostureCheckDef_Process{
				{OsType: "Linux", Path: "/usr/bin/agent"},
			},
		},
	}
	sub.servicesById = map[string]*edge_client_pb.ServiceDef{
		"svc-active":   {Id: "svc-active", Name: "svc-active", PolicyIds: []string{"dial-policy"}},
		"svc-inactive": {Id: "svc-inactive", Name: "svc-inactive", PolicyIds: []string{"dial-policy"}},
	}
	c.mu.Unlock()

	svcActive := "svc-active"
	ctx.activeDials.Set(svcActive, &rest_model.ServiceDetail{BaseEntity: rest_model.BaseEntity{ID: &svcActive}})
	// An active service outside this router's view contributes nothing to its requirements.
	svcElsewhere := "svc-elsewhere"
	ctx.activeDials.Set(svcElsewhere, &rest_model.ServiceDetail{BaseEntity: rest_model.BaseEntity{ID: &svcElsewhere}})

	info, ok := c.routerQueryInfo(conn)
	require.True(t, ok, "an applied snapshot yields per-router state")

	require.Contains(t, info.QueryTypes, string(rest_model.PostureCheckTypeMAC))
	require.Contains(t, info.QueryTypes, string(rest_model.PostureCheckTypePROCESSMULTI))
	require.Contains(t, info.Processes, "/usr/bin/agent")
	require.NotContains(t, info.QueryTypes, string(rest_model.PostureCheckTypeDOMAIN))
}

// TestMergePushedServiceDetail locks in that the poll-to-push handoff loses no fields: pushed
// details overlay only the fields a router is authoritative for, while polled-only metadata
// (tags, role attributes, timestamps, terminator strategy, max idle time) is preserved.
func TestMergePushedServiceDetail(t *testing.T) {
	name := "svc"
	id := "svc-id"
	enc := true
	strategy := "smartrouting"
	maxIdle := int64(30000)
	roleAttrs := rest_model.Attributes{"sales"}
	existing := &rest_model.ServiceDetail{
		BaseEntity: rest_model.BaseEntity{
			ID:   &id,
			Tags: &rest_model.Tags{SubTags: rest_model.SubTags{"team": "blue"}},
		},
		Name:               &name,
		EncryptionRequired: &enc,
		TerminatorStrategy: &strategy,
		MaxIdleTimeMillis:  &maxIdle,
		RoleAttributes:     &roleAttrs,
		Permissions:        rest_model.DialBindArray{rest_model.DialBindDial},
	}

	pushed := &rest_model.ServiceDetail{
		BaseEntity:         rest_model.BaseEntity{ID: &id},
		Name:               &name,
		EncryptionRequired: &enc,
		Permissions:        rest_model.DialBindArray{rest_model.DialBindDial, rest_model.DialBindBind},
		Configs:            []string{"cfg-1"},
		Config:             map[string]map[string]interface{}{"type": {"hostname": "example"}},
	}

	merged := mergePushedServiceDetail(existing, pushed)

	require.Equal(t, pushed.Permissions, merged.Permissions, "push is authoritative for permissions")
	require.Equal(t, pushed.Configs, merged.Configs, "push is authoritative for config ids")
	require.Equal(t, pushed.Config, merged.Config, "push is authoritative for config bodies")
	require.Equal(t, &strategy, merged.TerminatorStrategy, "polled-only fields are preserved")
	require.Equal(t, &maxIdle, merged.MaxIdleTimeMillis, "polled-only fields are preserved")
	require.Equal(t, &roleAttrs, merged.RoleAttributes, "polled-only fields are preserved")
	require.NotNil(t, merged.Tags, "polled-only tags are preserved")
	require.Equal(t, rest_model.DialBindArray{rest_model.DialBindDial}, existing.Permissions,
		"the cached detail must not be mutated in place")
}

// TestChangeSetRemovesPolicyAndCheckDefs locks in that op:removed entries for policies and posture
// checks delete from the per-router structural cache instead of being upserted: a removed check
// whose def survived would keep feeding posture queries (and posture collection) for a requirement
// that no longer exists.
func TestChangeSetRemovesPolicyAndCheckDefs(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	snapshot, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
		Index:         1,
		PreviousIndex: -1,
		Services: []*edge_client_pb.ServiceDef{
			{Op: edge_client_pb.Op_Added, Id: "svc-1", Name: "svc-1", PolicyIds: []string{"pol-1"}},
		},
		Policies: []*edge_client_pb.PolicyDef{
			{Op: edge_client_pb.Op_Added, Id: "pol-1", Type: edge_client_pb.PolicyType_Dial, PostureCheckIds: []string{"chk-1"}},
		},
		PostureChecks: []*edge_client_pb.PostureCheckDef{
			{Op: edge_client_pb.Op_Added, Id: "chk-1", Type: string(rest_model.PostureCheckTypeMAC)},
		},
	})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: snapshot})

	removal, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
		Index:         2,
		PreviousIndex: 1,
		Policies: []*edge_client_pb.PolicyDef{
			{Op: edge_client_pb.Op_Removed, Id: "pol-1"},
		},
		PostureChecks: []*edge_client_pb.PostureCheckDef{
			{Op: edge_client_pb.Op_Removed, Id: "chk-1"},
		},
	})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: removal})

	c.mu.Lock()
	sub := c.routers[conn]
	_, policyPresent := sub.policiesById["pol-1"]
	_, checkPresent := sub.postureChecksById["chk-1"]
	c.mu.Unlock()
	require.False(t, policyPresent, "a removed policy def must leave the structural cache")
	require.False(t, checkPresent, "a removed posture-check def must leave the structural cache")
}

// TestOverlayPrunedOnStructuralRemoval locks in that posture pass/fail entries are pruned when
// the structure referencing them is removed: pass/fail for a policy or check no longer reachable
// from any service is stale state, and surfacing it (e.g. through RouterView) would lie to the
// app. Pruning runs after the full envelope applies, never entry-by-entry.
func TestOverlayPrunedOnStructuralRemoval(t *testing.T) {
	c := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}
	c.trackRouter(conn)

	snapshot, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
		Index:         1,
		PreviousIndex: -1,
		Services: []*edge_client_pb.ServiceDef{
			{Op: edge_client_pb.Op_Added, Id: "svc-1", Name: "svc-1", PolicyIds: []string{"pol-1", "pol-2"}},
		},
		Policies: []*edge_client_pb.PolicyDef{
			{Op: edge_client_pb.Op_Added, Id: "pol-1", Type: edge_client_pb.PolicyType_Dial, PostureCheckIds: []string{"chk-1"}},
			{Op: edge_client_pb.Op_Added, Id: "pol-2", Type: edge_client_pb.PolicyType_Bind, PostureCheckIds: []string{"chk-2"}},
		},
		PostureChecks: []*edge_client_pb.PostureCheckDef{
			{Op: edge_client_pb.Op_Added, Id: "chk-1", Type: string(rest_model.PostureCheckTypeMAC)},
			{Op: edge_client_pb.Op_Added, Id: "chk-2", Type: string(rest_model.PostureCheckTypeMAC)},
		},
	})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: snapshot})

	state, err := proto.Marshal(&edge_client_pb.PostureStateChange{
		Seq: 1,
		CheckStates: []*edge_client_pb.PostureStateChange_CheckState{
			{CheckId: "chk-1", IsPassing: true},
			{CheckId: "chk-2", IsPassing: false},
		},
		PolicyStates: []*edge_client_pb.PostureStateChange_PolicyState{
			{PolicyId: "pol-1", IsPassing: true},
			{PolicyId: "pol-2", IsPassing: false},
		},
	})
	require.NoError(t, err)
	c.HandlePostureStateChange(conn, &channel.Message{Body: state})

	// pol-2 (and with it chk-2) drops out of the service's references.
	removal, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
		Index:         2,
		PreviousIndex: 1,
		Services: []*edge_client_pb.ServiceDef{
			{Op: edge_client_pb.Op_Updated, Id: "svc-1", Name: "svc-1", PolicyIds: []string{"pol-1"}},
		},
		Policies: []*edge_client_pb.PolicyDef{
			{Op: edge_client_pb.Op_Removed, Id: "pol-2"},
		},
		PostureChecks: []*edge_client_pb.PostureCheckDef{
			{Op: edge_client_pb.Op_Removed, Id: "chk-2"},
		},
	})
	require.NoError(t, err)
	c.HandleServiceChangeSet(conn, &channel.Message{Body: removal})

	c.mu.Lock()
	sub := c.routers[conn]
	_, stalePolicy := sub.policyStates["pol-2"]
	_, staleCheck := sub.checkStates["chk-2"]
	_, livePolicy := sub.policyStates["pol-1"]
	_, liveCheck := sub.checkStates["chk-1"]
	c.mu.Unlock()

	require.False(t, stalePolicy, "removed policy's pass/fail must be pruned")
	require.False(t, staleCheck, "removed check's pass/fail must be pruned")
	require.True(t, livePolicy, "still-referenced policy state is retained")
	require.True(t, liveCheck, "still-referenced check state is retained")
}

// TestUnsubscribeRacingSubscribeDoesNotCommit locks in that a subscribe in flight when the app
// unsubscribes cannot land a stale subscribedRouters entry. Without the refusal, the stale entry
// keeps push counted as active (polling paused) while the coordinator drops every push from that
// router as untracked — the SDK goes silently blind.
func TestUnsubscribeRacingSubscribeDoesNotCommit(t *testing.T) {
	ctx := &ContextImpl{}
	coordinator := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}

	// A subscribe is in flight: reservation taken, router tracked, opt-in set.
	ctx.pushSubscriptionDesired.Store(true)
	require.True(t, ctx.reserveSubscription("addr1"))
	coordinator.trackRouter(conn)

	// The app unsubscribes while the subscribe is still in flight.
	ctx.pushSubscriptionDesired.Store(false)
	coordinator.clear()

	// The in-flight subscribe completes; its commit must be refused and leave no stale entry.
	require.False(t, ctx.commitSubscription("addr1", conn, coordinator))
	require.Empty(t, ctx.subscribedRouters, "no stale entry may survive the unsubscribe")
	require.Empty(t, ctx.subscribingRouters, "the reservation is released either way")

	// The caller-side cleanup tells the router to stop pushing (the subscribe may have reached it
	// after the opt-out broadcast).
	ctx.undoOrphanedSubscription("addr1", conn, coordinator)
	require.Equal(t, 1, conn.unsubscribeCalls)
}

// TestResubscribeAfterUnsubscribeRaceDoesNotCommitUntracked covers the fast unsubscribe/resubscribe
// variant: the opt-in flag is back on when the stale subscribe completes, but the coordinator no
// longer tracks its conn (the unsubscribe cleared it), so its pushes would still be dropped —
// the commit must be refused on tracking, not just on the flag.
func TestResubscribeAfterUnsubscribeRaceDoesNotCommitUntracked(t *testing.T) {
	ctx := &ContextImpl{}
	coordinator := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}

	ctx.pushSubscriptionDesired.Store(true)
	require.True(t, ctx.reserveSubscription("addr1"))
	coordinator.trackRouter(conn)

	// Unsubscribe then immediate resubscribe: desired flips back on, tracking stays cleared.
	ctx.pushSubscriptionDesired.Store(false)
	coordinator.clear()
	ctx.pushSubscriptionDesired.Store(true)

	require.False(t, ctx.commitSubscription("addr1", conn, coordinator),
		"an untracked conn must not commit even with the opt-in back on")
	require.Empty(t, ctx.subscribedRouters)
}

// TestCommitSubscriptionHappyPath pins the normal flow: opt-in set and conn tracked commits the
// subscription and releases the reservation.
func TestCommitSubscriptionHappyPath(t *testing.T) {
	ctx := &ContextImpl{}
	coordinator := newSubscriptionCoordinator(nil)
	conn := &stubRouterConn{name: "r1"}

	ctx.pushSubscriptionDesired.Store(true)
	require.True(t, ctx.reserveSubscription("addr1"))
	coordinator.trackRouter(conn)

	require.True(t, ctx.commitSubscription("addr1", conn, coordinator))
	require.Contains(t, ctx.subscribedRouters, "addr1")
	require.Empty(t, ctx.subscribingRouters)
}

// TestSubscriptionsToDrop locks in that the idle sweep never removes the last subscription.
func TestSubscriptionsToDrop(t *testing.T) {
	require.Equal(t, 0, subscriptionsToDrop(0, 1), "no idle routers, nothing to drop")
	require.Equal(t, 0, subscriptionsToDrop(1, 1), "the only subscription is retained even when idle")
	require.Equal(t, 2, subscriptionsToDrop(2, 3), "idle routers drop while a non-idle one remains")
	require.Equal(t, 2, subscriptionsToDrop(3, 3), "all idle: retain exactly one")
	require.Equal(t, 0, subscriptionsToDrop(0, 0), "no subscriptions at all")
}
