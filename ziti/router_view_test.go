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

func newRouterViewTestContext(t *testing.T) *ContextImpl {
	closeNotify := make(chan struct{})
	t.Cleanup(func() { close(closeNotify) })
	ctx := &ContextImpl{
		options:            &Options{},
		routerConnections:  cmap.New[edge.RouterConn](),
		services:           cmap.New[*rest_model.ServiceDetail](),
		sessions:           cmap.New[*rest_model.SessionDetail](),
		serviceEdgeRouters: cmap.New[[]*rest_model.SessionEdgeRouter](),
		intercepts:         cmap.New[*edge.InterceptV1Config](),
		EventEmmiter:       events.New(),
		closeNotify:        closeNotify,
	}
	ctx.subscriptionCoordinator.Store(newSubscriptionCoordinator(ctx))
	return ctx
}

// pushedSnapshot is a full-reset ServiceChangeSet with one service granted by one dial policy
// carrying one MAC posture check.
func pushedSnapshot(t *testing.T) *channel.Message {
	body, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
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
	return &channel.Message{Body: body}
}

func pushedPostureState(t *testing.T, seq uint64, checkPassing, policyPassing bool) *channel.Message {
	body, err := proto.Marshal(&edge_client_pb.PostureStateChange{
		Seq: seq,
		CheckStates: []*edge_client_pb.PostureStateChange_CheckState{
			{CheckId: "chk-1", IsPassing: checkPassing},
		},
		PolicyStates: []*edge_client_pb.PostureStateChange_PolicyState{
			{PolicyId: "pol-1", IsPassing: policyPassing},
		},
	})
	require.NoError(t, err)
	return &channel.Message{Body: body}
}

// TestGetRouterViews locks in the public per-router view: connection facts composed with each
// router's pushed services, the posture pass/fail overlaid into PostureQueries, and honest
// unknowns for routers without an applied snapshot.
func TestGetRouterViews(t *testing.T) {
	req := require.New(t)
	ctx := newRouterViewTestContext(t)
	coordinator := ctx.getSubscriptionCoordinator()

	subscribedConn := &stubRouterConn{name: "r1", capable: true}
	bareConn := &stubRouterConn{name: "r2", capable: false}
	ctx.routerConnections.Set(subscribedConn.GetRouterAddr(), subscribedConn)
	ctx.routerConnections.Set(bareConn.GetRouterAddr(), bareConn)
	ctx.subscribedRouters = map[string]struct{}{subscribedConn.GetRouterAddr(): {}}

	coordinator.trackRouter(subscribedConn)
	coordinator.HandleServiceChangeSet(subscribedConn, pushedSnapshot(t))
	coordinator.HandlePostureStateChange(subscribedConn, pushedPostureState(t, 1, true, false))

	views := ctx.GetRouterViews()
	req.Len(views, 2)

	// Ordered by address: r1.addr before r2.addr.
	pushed := views[0]
	req.Equal("r1.id", pushed.Id)
	req.Equal("r1", pushed.Name)
	req.Equal("r1.addr", pushed.Address)
	req.True(pushed.Connected)
	req.True(pushed.SupportsPush)
	req.True(pushed.Subscribed)
	req.True(pushed.IsAppView)
	req.Equal(int64(1), pushed.StructuralIndex)
	req.Len(pushed.Services, 1)

	svc := pushed.Services[0]
	req.Equal("svc-1", svc.Id)
	req.Equal("svc-1", svc.Name)
	req.Equal([]string{RouterViewPermissionDial}, svc.Permissions)
	req.Len(svc.Policies, 1)
	policy := svc.Policies[0]
	req.Equal("pol-1", policy.Id)
	req.Equal(RouterViewPermissionDial, policy.Type)
	req.NotNil(policy.IsPassing, "policy pass/fail must come from the pushed state")
	req.False(*policy.IsPassing)
	req.Len(policy.PostureChecks, 1)
	check := policy.PostureChecks[0]
	req.Equal("chk-1", check.Id)
	req.Equal(string(rest_model.PostureCheckTypeMAC), check.Type)
	req.NotNil(check.IsPassing, "check pass/fail must come from the pushed state")
	req.True(*check.IsPassing)

	bare := views[1]
	req.Equal("r2", bare.Name)
	req.True(bare.Connected)
	req.False(bare.SupportsPush)
	req.False(bare.Subscribed)
	req.False(bare.IsAppView)
	req.Equal(int64(-1), bare.StructuralIndex)
	req.Nil(bare.Services, "a router with no applied snapshot has an unknown view, not an empty one")
}

// TestRouterViewOverlayUnknownStaysNil locks in that posture entries with no pushed state remain
// nil (unknown) rather than defaulting to a pass/fail value.
func TestRouterViewOverlayUnknownStaysNil(t *testing.T) {
	req := require.New(t)
	ctx := newRouterViewTestContext(t)
	coordinator := ctx.getSubscriptionCoordinator()

	conn := &stubRouterConn{name: "r1", capable: true}
	ctx.routerConnections.Set(conn.GetRouterAddr(), conn)

	coordinator.trackRouter(conn)
	coordinator.HandleServiceChangeSet(conn, pushedSnapshot(t))
	// No PostureStateChange applied.

	views := ctx.GetRouterViews()
	req.Len(views, 1)
	req.Len(views[0].Services, 1)
	policy := views[0].Services[0].Policies[0]
	req.Nil(policy.IsPassing, "no pushed policy state: unknown, not a default")
	req.Nil(policy.PostureChecks[0].IsPassing, "no pushed check state: unknown, not a default")
}

// TestRouterViewPolicyWithoutChecksVisible locks in that a granting policy with no posture checks
// is still listed on the service view with its id: policy visibility must not depend on posture
// checks existing.
func TestRouterViewPolicyWithoutChecksVisible(t *testing.T) {
	req := require.New(t)
	ctx := newRouterViewTestContext(t)
	coordinator := ctx.getSubscriptionCoordinator()

	conn := &stubRouterConn{name: "r1", capable: true}
	ctx.routerConnections.Set(conn.GetRouterAddr(), conn)
	coordinator.trackRouter(conn)

	body, err := proto.Marshal(&edge_client_pb.ServiceChangeSet{
		Index:         1,
		PreviousIndex: -1,
		Services: []*edge_client_pb.ServiceDef{
			{Op: edge_client_pb.Op_Added, Id: "svc-1", Name: "svc-1", PolicyIds: []string{"pol-bare"}},
		},
		Policies: []*edge_client_pb.PolicyDef{
			{Op: edge_client_pb.Op_Added, Id: "pol-bare", Type: edge_client_pb.PolicyType_Bind},
		},
	})
	req.NoError(err)
	coordinator.HandleServiceChangeSet(conn, &channel.Message{Body: body})

	views := ctx.GetRouterViews()
	req.Len(views, 1)
	req.Len(views[0].Services, 1)
	svc := views[0].Services[0]
	req.Equal([]string{RouterViewPermissionBind}, svc.Permissions)
	req.Len(svc.Policies, 1, "a policy without posture checks must still be visible")
	req.Equal("pol-bare", svc.Policies[0].Id)
	req.Equal(RouterViewPermissionBind, svc.Policies[0].Type)
	req.Empty(svc.Policies[0].PostureChecks)
	req.NotNil(svc.Policies[0].PostureChecks, "no checks renders as empty, not null")
}

// TestRouterViewChangedEventing locks in the single public change event: it fires for structural
// applies and posture state applies, carries the router's complete view, and its listeners run
// with no coordinator locks held (a listener that re-enters the SDK must not deadlock).
func TestRouterViewChangedEventing(t *testing.T) {
	req := require.New(t)
	ctx := newRouterViewTestContext(t)
	coordinator := ctx.getSubscriptionCoordinator()

	conn := &stubRouterConn{name: "r1", capable: true}
	ctx.routerConnections.Set(conn.GetRouterAddr(), conn)

	views := make(chan RouterView, 16)
	remove := ctx.AddRouterViewChangedListener(func(_ Context, view RouterView) {
		coordinator.markActive(conn) // re-enters the coordinator exactly like a listener-triggered dial
		views <- view
	})
	defer remove()

	coordinator.trackRouter(conn)
	coordinator.HandleServiceChangeSet(conn, pushedSnapshot(t))

	// Coalescing may fold the track + snapshot into one emission; wait for the view that shows
	// the applied snapshot.
	req.Eventually(func() bool {
		select {
		case view := <-views:
			return view.StructuralIndex == 1 && len(view.Services) == 1
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "a structural apply must emit the router's full view")

	coordinator.HandlePostureStateChange(conn, pushedPostureState(t, 1, true, true))

	req.Eventually(func() bool {
		select {
		case view := <-views:
			if len(view.Services) != 1 || len(view.Services[0].Policies) != 1 {
				return false
			}
			policy := view.Services[0].Policies[0]
			return policy.IsPassing != nil && *policy.IsPassing
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "a posture state apply must emit the view with pass/fail overlaid")
}
