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

//go:build acceptance

package tests

import (
	"testing"
	"time"

	edgeApis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// Test_DialProtocolNegotiation verifies dial protocol selection: the SDK uses
// the sessionless ConnectV2 path exactly when the router advertises the
// capability and the API session is OIDC, and otherwise the legacy session-based
// V1 path — asserted against the observed dial event, never inferred from a
// version number, so a silent fallback fails the test. With
// ZITI_ACCEPTANCE_REQUIRE_V2 the test additionally fails if the environment
// can't exercise ConnectV2 at all, so the CI job dedicated to ConnectV2 coverage
// can't go green by adaptively passing on the V1 path.
func Test_DialProtocolNegotiation(t *testing.T) {
	h := shared
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	svc := h.CreateService(t, "echo")

	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())
	clientCtx := h.NewSdkContext(t, clientID)

	var dialEvents []ziti.DialEvent
	removeListener := clientCtx.Events().AddDialListener(func(_ ziti.Context, evt ziti.DialEvent) {
		dialEvents = append(dialEvents, evt)
	})
	t.Cleanup(removeListener)

	// negotiated dial: the data plane must work regardless of the path taken
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "negotiated path")
	require.NotEmpty(t, dialEvents)
	negotiated := dialEvents[len(dialEvents)-1]
	require.NoError(t, negotiated.Err)
	require.False(t, negotiated.Forced)

	// compute the expected protocol from capability + auth mode, both observed
	// independently of the dial outcome
	isOidc := harness.ApiSessionType(t, clientCtx) == edgeApis.ApiSessionTypeOidc
	v2Capable := harness.RouterSupportsConnectV2(t, clientCtx, r.Name())
	expected := edge.DialProtocolConnectV1
	if v2Capable && isOidc {
		expected = edge.DialProtocolConnectV2
	}
	t.Logf("router connect-v2 capable: %v, oidc session: %v -> expecting %s (got %s)",
		v2Capable, isOidc, expected, negotiated.Protocol)

	if harness.RequireV2() {
		require.True(t, v2Capable,
			"%s: the router must advertise ConnectV2; this job exists to exercise V2, not to pass adaptively as V1",
			harness.RequireV2Env)
		require.True(t, isOidc, "%s: the session must be OIDC for ConnectV2", harness.RequireV2Env)
	}
	require.Equal(t, expected, negotiated.Protocol,
		"the SDK must take the path the negotiation inputs dictate, never silently fall back")

	// ForceConnectV1 must yield V1 with the Forced flag, regardless of capability
	dialEvents = nil
	forceV1 := true
	conn := dialWithOptionsRetry(t, clientCtx, svc.Name(), &ziti.DialOptions{
		ConnectTimeout: 30 * time.Second,
		ForceConnectV1: &forceV1,
	})
	t.Cleanup(func() { _ = conn.Close() })
	require.NotEmpty(t, dialEvents)
	forced := dialEvents[len(dialEvents)-1]
	require.NoError(t, forced.Err)
	require.Equal(t, edge.DialProtocolConnectV1, forced.Protocol, "ForceConnectV1 must take V1")
	require.True(t, forced.Forced, "the event must mark the V1 path as forced")
}
