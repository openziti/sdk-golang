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

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

// requireServiceEvent waits for an event naming service on ch, draining events
// for other services until it matches or the deadline elapses.
func requireServiceEvent(t testing.TB, ch <-chan string, service, desc string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case got := <-ch:
			if got == service {
				return
			}
		case <-deadline:
			t.Fatalf("%s: never observed event for service %s", desc, service)
		}
	}
}

// Test_ServiceUpdatePropagation covers acceptance batch item #6c: after an
// initial dial, editing a service's access (policy edits) is reflected by the
// SDK. The ServiceChanged/Removed/Added events fire on a forced refresh, and the
// sessionless service-edge-router cache invalidates rather than dialing stale
// data: a dial fails once access is revoked and succeeds again once re-granted.
func Test_ServiceUpdatePropagation(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	svc := h.CreateService(t, "echo")
	h.GrantBind(t, svc, hostID)
	dialPolicy := h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())

	clientCtx := h.NewSdkContext(t, clientID)
	// baseline: the service is dialable before any access edits
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "service-update baseline")

	added := make(chan string, 8)
	changed := make(chan string, 8)
	removed := make(chan string, 8)
	clientCtx.Events().AddServiceAddedListener(func(_ ziti.Context, s *rest_model.ServiceDetail) { added <- *s.Name })
	clientCtx.Events().AddServiceChangedListener(func(_ ziti.Context, s *rest_model.ServiceDetail) { changed <- *s.Name })
	clientCtx.Events().AddServiceRemovedListener(func(_ ziti.Context, s *rest_model.ServiceDetail) { removed <- *s.Name })

	// CHANGED: granting Bind changes the client's permissions on the service,
	// which the SDK detects as a service change.
	bindPolicy := h.GrantBind(t, svc, clientID)
	require.NoError(t, clientCtx.RefreshServices())
	requireServiceEvent(t, changed, svc.Name(), "ServiceChanged after permission grant")

	// REMOVED: revoke all access; the service should drop out of the client's
	// view and its cached session/ER data should be invalidated.
	dialPolicy.Delete(t)
	bindPolicy.Delete(t)
	require.NoError(t, clientCtx.RefreshServices())
	requireServiceEvent(t, removed, svc.Name(), "ServiceRemoved after access revoke")

	// the SDK must reflect the revocation, not dial stale cached data
	_, err := clientCtx.Dial(svc.Name())
	require.Error(t, err, "dial after access revoke should fail rather than use stale cache")

	// ADDED: re-grant dial; the service reappears and dials again
	h.GrantDial(t, svc, clientID)
	require.NoError(t, clientCtx.RefreshServices())
	requireServiceEvent(t, added, svc.Name(), "ServiceAdded after re-grant")
	requireEchoRoundTrip(t, clientCtx, svc.Name(), "service-update after re-grant")
}
