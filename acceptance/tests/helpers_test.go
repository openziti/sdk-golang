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
	"io"
	"testing"
	"time"

	edgeApis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// startEchoServer hosts service on hostCtx with an echo handler, advertising
// SDK-hosted xgress on the bind (see startEchoServerFC).
func startEchoServer(t testing.TB, hostCtx ziti.Context, service string) {
	t.Helper()
	startEchoServerFC(t, hostCtx, service, true)
}

// startEchoServerFC hosts service on hostCtx with an echo handler: each accepted
// conn is read to EOF (the dialer's half-close), echoed back, and closed.
// sdkXgress controls whether the bind advertises SDK-hosted xgress: when the
// router supports it, dials to this terminator run SDK xgress on both ends (the
// path the suite primarily exercises); otherwise the host is a legacy terminator
// and the router bridges xgress to it. Returns once the terminator is
// established; the listener closes with t.
func startEchoServerFC(t testing.TB, hostCtx ziti.Context, service string, sdkXgress bool) {
	t.Helper()
	listener, err := hostCtx.ListenWithOptions(service, &ziti.ListenOptions{
		WaitForNEstablishedListeners: 1,
		ConnectTimeout:               30 * time.Second,
		SdkFlowControl:               &sdkXgress,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				// a deadline so a broken dialer-to-host data path can't strand
				// this goroutine; the dialer then sees a short echo and fails
				// its comparison promptly instead of hanging
				_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				data, _ := io.ReadAll(conn)
				_, _ = conn.Write(data)
				_ = conn.Close()
			}()
		}
	}()
}

// requireEchoRoundTrip dials service from ctx and proves the data plane: write,
// half-close, read the echo to EOF, compare.
func requireEchoRoundTrip(t testing.TB, ctx ziti.Context, service string, payload string) {
	t.Helper()
	conn := dialWithRetry(t, ctx, service)
	defer func() { _ = conn.Close() }()

	_, err := conn.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite(), "half-close the send side")

	// bound the read so a data-plane failure surfaces as a directed error in
	// seconds rather than a test-binary timeout with a goroutine dump
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(30*time.Second)))
	echoed, err := io.ReadAll(conn)
	require.NoError(t, err,
		"no echo within 30s: the data plane delivered nothing back (write accepted, read starved)")
	require.Equal(t, payload, string(echoed))
}

// dialWithRetry performs the first dial after setup with a bounded retry, per the
// design: router readiness can precede full dial readiness (terminator and policy
// propagation), so the first dial must not assert on a single attempt.
func dialWithRetry(t testing.TB, ctx ziti.Context, service string) edge.Conn {
	t.Helper()
	return dialWithOptionsRetry(t, ctx, service, nil)
}

// dialWithOptionsRetry is dialWithRetry with explicit dial options.
func dialWithOptionsRetry(t testing.TB, ctx ziti.Context, service string, options *ziti.DialOptions) edge.Conn {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		var conn edge.Conn
		var err error
		if options != nil {
			conn, err = ctx.DialWithOptions(service, options)
		} else {
			conn, err = ctx.Dial(service)
		}
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	t.Fatalf("dialing %s never succeeded: %v", service, lastErr)
	return nil
}

// expectedDialProtocol computes which protocol a dial from ctx through the named
// router should negotiate, from capability and auth mode observed independently
// of any dial outcome.
func expectedDialProtocol(t testing.TB, ctx ziti.Context, routerName string) edge.DialProtocol {
	t.Helper()
	isOidc := harness.ApiSessionType(t, ctx) == edgeApis.ApiSessionTypeOidc
	if harness.RouterSupportsConnectV2(t, ctx, routerName) && isOidc {
		return edge.DialProtocolConnectV2
	}
	return edge.DialProtocolConnectV1
}
