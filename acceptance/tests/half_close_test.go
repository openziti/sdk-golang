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

	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// Test_HalfClose_XgressClientToLegacyHost covers a back-compat seam: an xgress
// (ConnectV2) client half-closing its send side to a host that bound WITHOUT
// SDK xgress, so the router terminates xgress and bridges to a legacy edge host
// that reads to EOF. Such a host never negotiates native xgress EOF, so the
// client must signal half-close as a legacy edge FIN (carried as a payload
// header the router maps back onto edge.FlagsHeader) rather than the native EOF
// flag, which the host doesn't honor. Without that fallback the host's read
// never ends and the echo never comes back; the round trip would hang until the
// read deadline. The test first asserts the client actually negotiated the
// xgress path, so a silent V1 fallback can't make it pass without exercising
// the seam.
func Test_HalfClose_XgressClientToLegacyHost(t *testing.T) {
	h := shared
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	svc := h.CreateService(t, "echo")
	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	// legacy terminator: bind WITHOUT SDK xgress, so the router bridges xgress to
	// an edge host that reads to EOF
	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServerFC(t, hostCtx, svc.Name(), false)

	clientCtx := h.NewSdkContext(t, clientID)
	var dialEvents []ziti.DialEvent
	removeListener := clientCtx.Events().AddDialListener(func(_ ziti.Context, evt ziti.DialEvent) {
		dialEvents = append(dialEvents, evt)
	})
	t.Cleanup(removeListener)

	// the round trip half-closes the client's send side, then reads the echo to
	// EOF. On the xgress path this is the regression under test: without the
	// legacy-FIN fallback the host's read-to-EOF never ends and this hangs to the
	// read deadline. (The capability that gates the path is observable only after
	// a dial establishes the router connection, so the round trip comes first.)
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "xgress-client-to-legacy-host half-close")

	require.NotEmpty(t, dialEvents)
	negotiated := dialEvents[len(dialEvents)-1]
	require.NoError(t, negotiated.Err)

	// the seam only exists for an xgress client; on the V1 path the legacy edge
	// conn already emits edge.FIN. Honor ZITI_ACCEPTANCE_REQUIRE_V2 so the
	// V2-dedicated job fails loudly rather than passing on the V1 path.
	if harness.RequireV2() {
		require.Equal(t, edge.DialProtocolConnectV2, negotiated.Protocol,
			"%s: this test must exercise the xgress path", harness.RequireV2Env)
	}
	if negotiated.Protocol != edge.DialProtocolConnectV2 {
		t.Skip("client negotiated V1; the xgress-to-legacy-host half-close seam is only exercised on the xgress path")
	}
}
