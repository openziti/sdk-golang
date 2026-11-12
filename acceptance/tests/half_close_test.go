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
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// hostedHalfClose is what a halfCloseHost saw on one accepted conn.
type hostedHalfClose struct {
	appData  string
	xgress   bool
	received string
	err      error
}

// halfCloseHost hosts one service bound without SDK flow control and one bound with it, so the
// conns it accepts are legacy and xgress conns respectively. Each accepted conn reads to EOF,
// echoes what it read, half-closes its send side and reports on results, then stays open until
// the test ends, so the dialer's EOF can only come from that half-close.
type halfCloseHost struct {
	results chan hostedHalfClose
	release chan struct{}
}

func startHalfCloseHost(t *testing.T, hostCtx ziti.Context, legacyService, xgressService string) *halfCloseHost {
	t.Helper()
	host := &halfCloseHost{
		results: make(chan hostedHalfClose, 16),
		release: make(chan struct{}),
	}
	t.Cleanup(func() { close(host.release) })

	for service, sdkFlowControl := range map[string]bool{legacyService: false, xgressService: true} {
		listener, err := hostCtx.ListenWithOptions(service, &ziti.ListenOptions{
			WaitForNEstablishedListeners: 1,
			ConnectTimeout:               30 * time.Second,
			SdkFlowControl:               &sdkFlowControl,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })

		go func() {
			for {
				conn, err := listener.AcceptEdge()
				if err != nil {
					return
				}
				go host.serve(conn)
			}
		}()
	}
	return host
}

func (host *halfCloseHost) serve(conn edge.Conn) {
	defer func() { _ = conn.Close() }()

	result := hostedHalfClose{appData: string(conn.GetAppData())}
	result.xgress, result.err = isXgressConn(conn)
	if result.err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var data []byte
		data, result.err = io.ReadAll(conn)
		result.received = string(data)
	}
	if result.err == nil {
		_, result.err = conn.Write([]byte(result.received))
	}
	if result.err == nil {
		result.err = conn.CloseWrite()
	}
	host.results <- result
	<-host.release
}

// requireResult waits for what the host saw on the conn dialed with appData, discarding results
// left by earlier dials.
func (host *halfCloseHost) requireResult(t *testing.T, appData string) hostedHalfClose {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case result := <-host.results:
			if result.appData == appData {
				return result
			}
		case <-timeout:
			t.Fatal("the host never finished its side of the half-close")
		}
	}
}

// isXgressConn reports whether conn carries its data over an SDK xgress. Only xgress conns
// include their xgress in GetState.
func isXgressConn(conn edge.Conn) (bool, error) {
	var state map[string]any
	if err := json.Unmarshal([]byte(conn.GetState()), &state); err != nil {
		return false, err
	}
	_, found := state["xg"]
	return found, nil
}

// dialEventRecorder keeps the dial events a context emits.
type dialEventRecorder struct {
	lock   sync.Mutex
	events []ziti.DialEvent
}

func recordDialEvents(t *testing.T, ctx ziti.Context) *dialEventRecorder {
	recorder := &dialEventRecorder{}
	t.Cleanup(ctx.Events().AddDialListener(func(_ ziti.Context, evt ziti.DialEvent) {
		recorder.lock.Lock()
		defer recorder.lock.Unlock()
		recorder.events = append(recorder.events, evt)
	}))
	return recorder
}

func (recorder *dialEventRecorder) last(t *testing.T) ziti.DialEvent {
	t.Helper()
	recorder.lock.Lock()
	defer recorder.lock.Unlock()
	require.NotEmpty(t, recorder.events, "no dial event was emitted")
	return recorder.events[len(recorder.events)-1]
}

// relaysHalfCloseToLegacyDialer reports whether routers of version v turn an xgress host's
// half-close into an edge FIN for a dialer without SDK flow control, which they do from 1.6.21
// on the 1.6 line and from 2.0.6.
func relaysHalfCloseToLegacyDialer(v harness.Version) bool {
	return v.AtLeast("2.0.6") || (v.AtLeast("1.6.21") && !v.AtLeast("2.0.0"))
}

// Test_HalfClose checks half-close in both directions for every pairing of dialing conn (a V1
// legacy conn, a V1 conn with SDK flow control, and a ConnectV2 conn) with hosted conn (legacy
// or xgress). The dialer half-closes its send side; the host reads to EOF, echoes, and
// half-closes its own; the dialer reads the echo to EOF. Each side's EOF can only come from the
// other's half-close, since both conns stay open until the round trip is done. Each pairing
// first checks it got the conn types it names, so a silent fallback can't pass for it.
//
// An xgress dialer to a legacy host is the back-compat seam: such a host never negotiates
// native xgress EOF, so the dialer must signal its half-close as a legacy edge FIN, carried as a
// payload header the router maps back onto edge.FlagsHeader. Without that fallback the host's
// read never ends.
//
// The ConnectV2 pairings need router support and an OIDC session. Without them they skip, unless
// ZITI_ACCEPTANCE_REQUIRE_V2 makes them fail. A legacy dialer to an xgress host skips on routers
// that don't relay the host's half-close (see relaysHalfCloseToLegacyDialer).
func Test_HalfClose(t *testing.T) {
	h := shared // shared test harness, set up in main_test.go
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	legacyHostSvc := h.CreateService(t, "legacy-host")
	xgressHostSvc := h.CreateService(t, "xgress-host")
	for _, svc := range []*harness.Service{legacyHostSvc, xgressHostSvc} {
		h.GrantBind(t, svc, hostID)
		h.GrantDial(t, svc, clientID)
		h.GrantServiceRouterAccess(t, svc, r)
	}
	h.GrantRouterAccess(t, r, hostID, clientID)

	host := startHalfCloseHost(t, h.NewSdkContext(t, hostID), legacyHostSvc.Name(), xgressHostSvc.Name())
	clientCtx := h.NewSdkContext(t, clientID)
	dialEvents := recordDialEvents(t, clientCtx)

	yes, no := true, false
	dialers := []struct {
		name     string
		options  ziti.DialOptions
		protocol edge.DialProtocol
		xgress   bool
	}{
		{"v1-legacy", ziti.DialOptions{ForceConnectV1: &yes, SdkFlowControl: &no}, edge.DialProtocolConnectV1, false},
		{"v1-xgress", ziti.DialOptions{ForceConnectV1: &yes, SdkFlowControl: &yes}, edge.DialProtocolConnectV1, true},
		{"v2", ziti.DialOptions{}, edge.DialProtocolConnectV2, true},
	}
	hosts := []struct {
		name    string
		service *harness.Service
		xgress  bool
	}{
		{"legacy-host", legacyHostSvc, false},
		{"xgress-host", xgressHostSvc, true},
	}

	for _, dialer := range dialers {
		for _, hosted := range hosts {
			t.Run(dialer.name+"-to-"+hosted.name, func(t *testing.T) {
				// the V1 pairings run first, so the router connection that reports V2 support
				// is up by the time the V2 pairings check it
				if dialer.protocol == edge.DialProtocolConnectV2 &&
					expectedDialProtocol(t, clientCtx, r.Name()) != edge.DialProtocolConnectV2 {
					require.False(t, harness.RequireV2(), "%s: the environment doesn't support ConnectV2", harness.RequireV2Env)
					t.Skip("the router doesn't support ConnectV2 for this session")
				}
				if !dialer.xgress && hosted.xgress && !relaysHalfCloseToLegacyDialer(h.Version()) {
					t.Skipf("ziti %s doesn't relay an xgress host's half-close to a legacy dialer", h.Version())
				}

				options := dialer.options
				options.ConnectTimeout = 30 * time.Second
				options.AppData = []byte(t.Name())
				conn := dialWithOptionsRetry(t, clientCtx, hosted.service.Name(), &options)
				defer func() { _ = conn.Close() }()

				require.Equal(t, dialer.protocol, dialEvents.last(t).Protocol, "dial protocol")
				xgress, err := isXgressConn(conn)
				require.NoError(t, err)
				require.Equal(t, dialer.xgress, xgress, "the dialer got the wrong conn type")

				payload := "half-close " + t.Name()
				_, err = conn.Write([]byte(payload))
				require.NoError(t, err)
				require.NoError(t, conn.CloseWrite(), "half-close the dialer's send side")

				require.NoError(t, conn.SetReadDeadline(time.Now().Add(30*time.Second)))
				echoed, err := io.ReadAll(conn)
				require.NoError(t, err, "the dialer never read to EOF: the host's half-close didn't arrive")
				require.Equal(t, payload, string(echoed))

				result := host.requireResult(t, t.Name())
				require.NoError(t, result.err, "the host's side of the half-close failed")
				require.Equal(t, hosted.xgress, result.xgress, "the host got the wrong conn type")
				require.Equal(t, payload, result.received)
			})
		}
	}
}
