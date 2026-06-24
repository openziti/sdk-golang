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

	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// acceptedConnInfo captures the dialer-supplied metadata the host sees on an
// accepted connection.
type acceptedConnInfo struct {
	sourceIdentifier   string
	appData            []byte
	dialerIdentityId   string
	dialerIdentityName string
}

// startMetadataCapturingServer hosts service on hostCtx and, for the first
// accepted connection, records the dialer metadata the host can observe
// (caller id, app data, dialer identity) before echoing and closing. The
// captured info is delivered on the returned channel.
func startMetadataCapturingServer(t testing.TB, hostCtx ziti.Context, service string) <-chan acceptedConnInfo {
	t.Helper()
	sdkXgress := true
	listener, err := hostCtx.ListenWithOptions(service, &ziti.ListenOptions{
		WaitForNEstablishedListeners: 1,
		ConnectTimeout:               30 * time.Second,
		SdkFlowControl:               &sdkXgress,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	infoC := make(chan acceptedConnInfo, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// edge.Conn carries the dialer metadata accessors; Accept returns a
		// net.Conn whose concrete type is an edge ServiceConn.
		if sc, ok := conn.(edge.ServiceConn); ok {
			infoC <- acceptedConnInfo{
				sourceIdentifier:   sc.SourceIdentifier(),
				appData:            sc.GetAppData(),
				dialerIdentityId:   sc.GetDialerIdentityId(),
				dialerIdentityName: sc.GetDialerIdentityName(),
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write(data)
		_ = conn.Close()
	}()
	return infoC
}

// Test_ConnSemantics_DialerMetadata proves the dialer metadata round-trip: the
// caller id (the dialing identity's name, set automatically by the SDK) and the
// dialer-supplied AppData are visible on the host's accepted connection. It also
// re-exercises the core stream contract (half-close + read-to-EOF) via the echo
// round trip, so the metadata assertions ride on a proven data plane rather than
// a connection that silently failed to carry data.
func Test_ConnSemantics_DialerMetadata(t *testing.T) {
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
	infoC := startMetadataCapturingServer(t, hostCtx, svc.Name())

	clientCtx := h.NewSdkContext(t, clientID)

	appData := []byte("app-data-round-trip")
	conn := dialWithOptionsRetry(t, clientCtx, svc.Name(), &ziti.DialOptions{
		ConnectTimeout: 30 * time.Second,
		AppData:        appData,
	})
	defer func() { _ = conn.Close() }()

	payload := "dialer-metadata round-trip"
	_, err := conn.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite(), "half-close the send side")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(30*time.Second)))
	echoed, err := io.ReadAll(conn)
	require.NoError(t, err, "no echo within 30s: the data plane delivered nothing back")
	require.Equal(t, payload, string(echoed))

	select {
	case info := <-infoC:
		require.Equal(t, clientID.Name(), info.sourceIdentifier,
			"host should see the dialing identity's name as the caller id")
		require.Equal(t, appData, info.appData,
			"host should see the dialer-supplied app data")
		// the dialer identity (id + name) is a 2.0+ capability; older controllers
		// do not populate the dialer identity headers on the dial request
		if h.Version().AtLeast("2.0.0") {
			require.Equal(t, clientID.Name(), info.dialerIdentityName,
				"host should see the dialer identity name")
			require.NotEmpty(t, info.dialerIdentityId,
				"host should see the dialer identity id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("host never reported accepted-connection metadata")
	}
}
