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
	"time"

	"github.com/stretchr/testify/require"
)

// Test_Revocation_IdentityDelete covers acceptance batch item #4 (revocation
// enforcement): once a dialing identity is deleted, the controller enforces the
// revocation and the SDK can no longer dial the service. A freshly revoked
// identity may briefly dial on cached session state, so enforcement is asserted
// as eventual within a bounded window rather than on a single attempt.
//
// This covers the new-dial-refused path. Reaper-driven teardown of an already
// established circuit is a separate behavior (it needs a hold-open host and is
// reaper-interval sensitive) and is tracked as a follow-up.
func Test_Revocation_IdentityDelete(t *testing.T) {
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
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "revocation baseline")

	// revoke the client by deleting its identity
	h.Cli(t, "edge", "delete", "identity", clientID.Name())

	// enforcement: the client can no longer dial. Poll until the dial is refused,
	// closing any connection that still briefly succeeds on cached state.
	require.Eventually(t, func() bool {
		conn, err := clientCtx.Dial(svc.Name())
		if err == nil {
			_ = conn.Close()
			return false
		}
		return true
	}, 60*time.Second, time.Second, "dial should be refused after the identity is revoked")
}
