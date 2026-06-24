//go:build acceptance

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

package tests

import (
	"testing"

	"github.com/openziti/sdk-golang/acceptance/harness"
	edgeApis "github.com/openziti/sdk-golang/v2/edge-apis"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

// apiSessionToken returns the current api-session token for ctx.
func apiSessionToken(t testing.TB, ctx ziti.Context) string {
	t.Helper()
	apiSession := ctx.(*ziti.ContextImpl).CtrlClt.GetCurrentApiSession()
	require.NotNil(t, apiSession, "context has no current api session")
	return string(apiSession.GetToken())
}

// refreshApiSession refreshes ctx's api session, failing on a functional refresh
// error or an edge-router token propagation error.
func refreshApiSession(t testing.TB, ctx ziti.Context) {
	t.Helper()
	refreshErr, erErr := ctx.(*ziti.ContextImpl).RefreshApiSession()
	require.NoError(t, refreshErr, "api-session refresh should succeed")
	require.NoError(t, erErr, "edge-router token propagation should succeed after refresh")
}

// Test_TokenRefresh_DialContinuity covers acceptance batch item #6: across
// several api-session refreshes the context keeps dialing, and on OIDC each
// refresh rotates the access token (the new token propagates to the edge
// routers, so the next dial uses it).
func Test_TokenRefresh_DialContinuity(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
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
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "token-refresh baseline")

	// rotation is an OIDC property (the legacy session token is stable across a
	// refresh); only assert it on OIDC, but assert dial continuity either way.
	checkRotation := harness.ApiSessionType(t, clientCtx) == edgeApis.ApiSessionTypeOidc

	for i := 0; i < 3; i++ {
		prev := apiSessionToken(t, clientCtx)
		refreshApiSession(t, clientCtx)
		if checkRotation {
			require.NotEqual(t, prev, apiSessionToken(t, clientCtx),
				"each OIDC refresh should rotate the access token")
		}
		requireEchoRoundTrip(t, clientCtx, svc.Name(), "token-refresh dial after refresh")
	}
}

// Test_HostingContinuity_AcrossRefresh covers acceptance batch item #6b: a
// hosted terminator survives the host's api-session/token refresh. After the
// host refreshes, the terminator stays registered and the service keeps
// accepting dials. This is distinct from the dial path: bind/listen uses service
// sessions and terminators, which must ride the refresh.
func Test_HostingContinuity_AcrossRefresh(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
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
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "hosting-continuity baseline")

	// refresh the host's session twice; the terminator must survive each time
	for i := 0; i < 2; i++ {
		refreshApiSession(t, hostCtx)
		requireEchoRoundTrip(t, clientCtx, svc.Name(), "hosting-continuity dial after host refresh")
	}
}
