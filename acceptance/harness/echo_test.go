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

package harness

import (
	"io"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// Test_DialHostEcho is the data-plane smoke: a separate-process router, targeted
// policies, the SDK under test hosting a service and dialing it, with the echo
// exercising half-close (CloseWrite) and EOF propagation in both directions.
func Test_DialHostEcho(t *testing.T) {
	h := Start(t)
	r := h.AddRouter(t, "r1")

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	svc := h.CreateService(t, "echo")

	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	// contexts authenticate after the grants, so the service is visible
	hostCtx := h.NewSdkContext(t, hostID)
	clientCtx := h.NewSdkContext(t, clientID)

	listener, err := hostCtx.ListenWithOptions(svc.Name(), &ziti.ListenOptions{
		WaitForNEstablishedListeners: 1,
		ConnectTimeout:               30 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// echo server: read until the client's half-close EOF, write everything
	// back, then close, so the client sees its bytes and then EOF
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				data, _ := io.ReadAll(conn)
				_, _ = conn.Write(data)
				_ = conn.Close()
			}()
		}
	}()

	// dial events are emitted synchronously on the dialing goroutine, so the
	// captured slice is safe to read once the dial returns
	var dialEvents []ziti.DialEvent
	removeListener := clientCtx.Events().AddDialListener(func(_ ziti.Context, evt ziti.DialEvent) {
		dialEvents = append(dialEvents, evt)
	})
	t.Cleanup(removeListener)

	conn := dialWithRetry(t, clientCtx, svc.Name())
	defer func() { _ = conn.Close() }()

	// released routers don't advertise ConnectV2, so the SDK must negotiate V1;
	// once a capable line ships, this expectation becomes capability-driven (see
	// the V1/V2 negotiation test in the design doc)
	require.NotEmpty(t, dialEvents, "the dial must emit an event")
	last := dialEvents[len(dialEvents)-1] // earlier attempts may have failed and retried
	require.NoError(t, last.Err)
	require.Equal(t, edge.DialProtocolConnectV1, last.Protocol,
		"expected the V1 dial path against a non-ConnectV2-capable router")
	require.False(t, last.Forced, "V1 must be negotiated, not forced")
	require.Equal(t, r.Name(), last.RouterName)
	require.NotEmpty(t, last.CircuitId)

	msg := []byte("hello acceptance")
	_, err = conn.Write(msg)
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite(), "half-close the send side")

	echoed, err := io.ReadAll(conn) // reads the echo, then EOF from server close
	require.NoError(t, err)
	require.Equal(t, msg, echoed)
}

// dialWithRetry performs the first dial after bring-up with a bounded retry, per
// the design: TCP/online readiness can precede full dial readiness (terminator and
// policy propagation), so the first dial must not assert on a single attempt.
func dialWithRetry(t testing.TB, ctx ziti.Context, service string) edge.Conn {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := ctx.Dial(service)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	t.Fatalf("dialing %s never succeeded: %v", service, lastErr)
	return nil
}
