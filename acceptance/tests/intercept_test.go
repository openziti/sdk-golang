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
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

const (
	interceptV1ConfigType = "intercept.v1"
	clientV1ConfigType    = "ziti-tunneler-client.v1"
)

// requireEchoViaAddr resolves addr to a service via the context's intercepts and
// dials it with DialAddr, then proves the data plane with a write/half-close/
// read-to-EOF echo. It retries the initial dial like dialWithRetry, since
// terminator/policy propagation can lag router readiness.
func requireEchoViaAddr(t testing.TB, ctx ziti.Context, network, addr, payload string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := ctx.DialAddr(network, addr)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		defer func() { _ = conn.Close() }()

		_, err = conn.Write([]byte(payload))
		require.NoError(t, err)
		require.NoError(t, conn.CloseWrite(), "half-close the send side")
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(30*time.Second)))
		echoed, err := io.ReadAll(conn)
		require.NoError(t, err, "no echo within 30s on DialAddr conn")
		require.Equal(t, payload, string(echoed))
		return
	}
	t.Fatalf("DialAddr %s/%s never succeeded: %v", network, addr, lastErr)
}

// Test_InterceptDial covers acceptance batch item #6f for an intercept.v1
// config: the tunneler-style entry point. GetServiceForAddr scores an exact
// host+port match at 0 and rejects a non-matching port, and DialAddr resolves
// the address to that service and round-trips data.
func Test_InterceptDial(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
	r := h.DefaultRouter()

	const host = "intercept-v1.test"
	const port = 8080

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")

	cfg := h.CreateConfig(t, "intercept", interceptV1ConfigType,
		fmt.Sprintf(`{"protocols":["tcp"],"addresses":["%s"],"portRanges":[{"low":%d,"high":%d}]}`, host, port, port))
	svc := h.CreateServiceWithConfigs(t, "echo", cfg)
	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())

	clientCtx := h.NewSdkContextWithConfigTypes(t, clientID, interceptV1ConfigType)

	matched, score, err := clientCtx.GetServiceForAddr("tcp", host, port)
	require.NoError(t, err, "intercept should match the configured host:port")
	require.Equal(t, svc.Name(), *matched.Name)
	require.Equal(t, 0, score, "an exact host+port match scores 0")

	_, _, err = clientCtx.GetServiceForAddr("tcp", host, port+1)
	require.Error(t, err, "a non-matching port should resolve to no service")

	requireEchoViaAddr(t, clientCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), "intercept dial round-trip")
}

// Test_InterceptDial_ClientConfigConversion covers the #6f conversion path: a
// service carrying only a ziti-tunneler-client.v1 config is still addressable,
// because the SDK converts that config to an intercept (ClientConfigV1 ->
// InterceptV1). GetServiceForAddr matches the converted host+port and DialAddr
// round-trips.
func Test_InterceptDial_ClientConfigConversion(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
	r := h.DefaultRouter()

	const host = "client-cfg.test"
	const port = 8080

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")

	cfg := h.CreateConfig(t, "client", clientV1ConfigType,
		fmt.Sprintf(`{"hostname":"%s","port":%d}`, host, port))
	svc := h.CreateServiceWithConfigs(t, "echo", cfg)
	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())

	clientCtx := h.NewSdkContextWithConfigTypes(t, clientID, clientV1ConfigType)

	matched, _, err := clientCtx.GetServiceForAddr("tcp", host, port)
	require.NoError(t, err, "the client config should convert to a matchable intercept")
	require.Equal(t, svc.Name(), *matched.Name)

	requireEchoViaAddr(t, clientCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), "client-config dial round-trip")
}
