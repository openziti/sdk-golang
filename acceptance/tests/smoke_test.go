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

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

// Test_SdkAuthenticate exercises the SDK against the shared versioned controller:
// CLI-created and CLI-enrolled identity -> ziti.NewContext -> authenticate ->
// service list and current-identity round trip.
func Test_SdkAuthenticate(t *testing.T) {
	h := shared

	id := h.CreateIdentity(t, "client")
	ctx := h.NewSdkContext(t, id)

	services, err := ctx.GetServices()
	require.NoError(t, err)
	require.Empty(t, services, "no policies grant this identity any services")

	current, err := ctx.GetCurrentIdentity()
	require.NoError(t, err)
	require.NotNil(t, current.Name)
	require.Equal(t, id.Name(), *current.Name)
}

// Test_DialHostEcho is the core data-plane smoke: the SDK under test hosts a
// service and dials it through the shared router, with targeted policies granting
// exactly the needed access. The echo exercises half-close (CloseWrite) and EOF
// propagation in both directions, the service list is checked for content (not
// just liveness), and the dial event must report the expected negotiated
// protocol.
func Test_DialHostEcho(t *testing.T) {
	h := shared
	r := h.DefaultRouter()

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

	// discovery content: each identity sees the service with exactly the
	// permissions its policy grants, and lookup by name works
	requireServicePermissions(t, hostCtx, svc.Name(), rest_model.DialBindBind)
	requireServicePermissions(t, clientCtx, svc.Name(), rest_model.DialBindDial)

	startEchoServer(t, hostCtx, svc.Name())

	// dial events are emitted synchronously on the dialing goroutine, so the
	// captured slice is safe to read once the dial returns
	var dialEvents []ziti.DialEvent
	removeListener := clientCtx.Events().AddDialListener(func(_ ziti.Context, evt ziti.DialEvent) {
		dialEvents = append(dialEvents, evt)
	})
	t.Cleanup(removeListener)

	conn := dialWithRetry(t, clientCtx, svc.Name())
	defer func() { _ = conn.Close() }()

	// the negotiated path must match what capability + auth mode dictate; the
	// dedicated negotiation test covers the full matrix of cases
	require.NotEmpty(t, dialEvents, "the dial must emit an event")
	last := dialEvents[len(dialEvents)-1] // earlier attempts may have failed and retried
	require.NoError(t, last.Err)
	require.Equal(t, expectedDialProtocol(t, clientCtx, r.Name()), last.Protocol)
	require.False(t, last.Forced, "the path must be negotiated, not forced")
	require.Equal(t, r.Name(), last.RouterName)
	require.NotEmpty(t, last.CircuitId)

	msg := []byte("hello acceptance")
	_, err := conn.Write(msg)
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite(), "half-close the send side")

	echoed, err := io.ReadAll(conn) // reads the echo, then EOF from server close
	require.NoError(t, err)
	require.Equal(t, msg, echoed)
}

// requireServicePermissions asserts the context's service list contains the named
// service with exactly the given permissions, and that lookup by name agrees.
func requireServicePermissions(t testing.TB, ctx ziti.Context, serviceName string, perms ...rest_model.DialBind) {
	t.Helper()

	services, err := ctx.GetServices()
	require.NoError(t, err)

	var found *rest_model.ServiceDetail
	for i := range services {
		if services[i].Name != nil && *services[i].Name == serviceName {
			found = &services[i]
			break
		}
	}
	require.NotNil(t, found, "service %s must appear in GetServices", serviceName)
	require.ElementsMatch(t, perms, []rest_model.DialBind(found.Permissions),
		"service %s permissions", serviceName)

	byName, ok := ctx.GetService(serviceName)
	require.True(t, ok, "GetService(%s) must find the service", serviceName)
	require.Equal(t, *found.ID, *byName.ID)
}

