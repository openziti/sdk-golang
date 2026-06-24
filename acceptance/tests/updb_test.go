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

	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

// Test_AuthModes_Updb covers acceptance batch item #6d: a username/password
// (UPDB) identity authenticates through the SDK and dials a service, and the
// authenticated context survives an api-session token refresh (the new token is
// propagated to the edge routers) and keeps dialing. UPDB is a common consumer
// credential path distinct from cert and ext-JWT auth.
func Test_AuthModes_Updb(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateUpdbIdentity(t, "updb-client")
	svc := h.CreateService(t, "echo")
	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())

	clientCtx := h.NewUpdbSdkContext(t, clientID)
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "updb auth round-trip")

	// token refresh through the SDK context: refresh the api session and confirm
	// the context still dials after the new token propagates to the edge routers.
	refreshErr, erErr := clientCtx.(*ziti.ContextImpl).RefreshApiSession()
	require.NoError(t, refreshErr, "updb api-session refresh should succeed")
	require.NoError(t, erErr, "edge-router token propagation should succeed after refresh")
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "updb post-refresh round-trip")
}
