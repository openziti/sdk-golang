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
	"io"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// Test_XgressClientClosedOnHostClose verifies that when the hosting side closes
// a circuit, an xgress (ConnectV2) client conn reports *closed*, not merely EOF
// on the next read. The host echoes and closes; the teardown propagates back,
// the client's xgress finishes, and the conn must flip to IsClosed.
//
// Regression: the conn's closed state is set by the conn, but a router-driven
// teardown (a peer end-of-circuit here, or a StateClosed on access revocation)
// closes the xgress without the conn ever being told. The conn then kept
// reporting open until the underlying channel went away, so callers polling
// IsClosed (e.g. after posture revocation) never saw the close. The test first
// asserts the dial actually took the xgress path, so a silent V1 fallback can't
// make it pass without exercising the seam.
func Test_XgressClientClosedOnHostClose(t *testing.T) {
	h := shared // shared test harness, setup in main_test.go
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	svc := h.CreateService(t, "echo")
	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	// host echoes a single round trip then closes the conn, tearing the circuit down
	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())

	clientCtx := h.NewSdkContext(t, clientID)
	var dialEvents []ziti.DialEvent
	removeListener := clientCtx.Events().AddDialListener(func(_ ziti.Context, evt ziti.DialEvent) {
		dialEvents = append(dialEvents, evt)
	})
	t.Cleanup(removeListener)

	conn := dialWithRetry(t, clientCtx, svc.Name())
	defer func() { _ = conn.Close() }()

	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite(), "half-close the send side")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(30*time.Second)))
	echoed, err := io.ReadAll(conn)
	require.NoError(t, err, "no echo within 30s: the data plane delivered nothing back")
	require.Equal(t, "ping", string(echoed))

	require.NotEmpty(t, dialEvents)
	negotiated := dialEvents[len(dialEvents)-1]
	require.NoError(t, negotiated.Err)

	// the seam only exists for an xgress client; on the V1 path the legacy edge
	// conn already closes on StateClosed. Honor ZITI_ACCEPTANCE_REQUIRE_V2 so the
	// V2-dedicated job fails loudly rather than passing on the V1 path.
	if harness.RequireV2() {
		require.Equal(t, edge.DialProtocolConnectV2, negotiated.Protocol,
			"%s: this test must exercise the xgress path", harness.RequireV2Env)
	}
	if negotiated.Protocol != edge.DialProtocolConnectV2 {
		t.Skip("client negotiated V1; the xgress conn-close-on-teardown behavior is only exercised on the xgress path")
	}

	// The host has closed. The teardown propagates back, the client's xgress
	// finishes, and the conn must report closed. Before the fix the xgress closed
	// but the conn reported open until the channel went away.
	require.Eventually(t, conn.IsClosed, 10*time.Second, 50*time.Millisecond,
		"client conn should report closed after the host closed the circuit")
}
