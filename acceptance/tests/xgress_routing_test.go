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
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// Test_XgressPayloadRoutingByCircuitId is the interop guard for the SDK's
// connId-less xgress framing. On the ConnectV2 (xgress) path the SDK sends data
// payloads and acknowledgements with NO ConnIdHeader, relying on the router to
// route them by the circuit id carried in the message. If a target router
// required ConnIdHeader to route xgress payloads/acks, a sustained transfer
// would stall (payloads or acks misrouted or dropped) and this round trip would
// fail or time out.
//
// It moves enough data to span many xgress payloads and force windowed acks in
// both directions, so the ack path is genuinely exercised — a single small echo
// barely produces one ack, which would not exercise ack routing.
func Test_XgressPayloadRoutingByCircuitId(t *testing.T) {
	h := shared // shared test harness, setup in main_test.go
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

	conn := dialWithRetry(t, clientCtx, svc.Name())
	defer func() { _ = conn.Close() }()

	require.NotEmpty(t, dialEvents)
	negotiated := dialEvents[len(dialEvents)-1]
	require.NoError(t, negotiated.Err)

	// connId-less routing is the xgress-path contract; the V1-legacy mux still
	// routes by connId, so this only means anything on the xgress path. Honor
	// ZITI_ACCEPTANCE_REQUIRE_V2 so the V2-dedicated job fails loudly rather than
	// passing on the V1 path.
	if harness.RequireV2() {
		require.Equal(t, edge.DialProtocolConnectV2, negotiated.Protocol,
			"%s: this test must exercise the xgress path", harness.RequireV2Env)
	}
	if negotiated.Protocol != edge.DialProtocolConnectV2 {
		t.Skip("client negotiated V1; connId-less xgress routing is only exercised on the xgress path")
	}

	// a deterministic pattern so any misordering or corruption is visible
	sent := make([]byte, 512*1024)
	for i := range sent {
		sent[i] = byte(i * 31)
	}

	require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))
	_, err := conn.Write(sent)
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite(), "half-close the send side")

	echoed, err := io.ReadAll(conn)
	require.NoError(t, err,
		"bulk echo did not complete: connId-less payload/ack routing may have stalled against this router")
	require.Equal(t, len(sent), len(echoed), "echoed byte count differs from sent")
	require.True(t, bytes.Equal(sent, echoed), "echoed data differs from sent")
}
