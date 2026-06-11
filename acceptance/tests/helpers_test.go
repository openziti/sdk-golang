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

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
)

// startEchoServer hosts service on hostCtx with an echo handler: each accepted
// conn is read to EOF (the dialer's half-close), echoed back, and closed.
// Returns once the terminator is established; the listener closes with t.
func startEchoServer(t testing.TB, hostCtx ziti.Context, service string) {
	t.Helper()
	listener, err := hostCtx.ListenWithOptions(service, &ziti.ListenOptions{
		WaitForNEstablishedListeners: 1,
		ConnectTimeout:               30 * time.Second,
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

	echoed, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, payload, string(echoed))
}

// dialWithRetry performs the first dial after setup with a bounded retry, per the
// design: router readiness can precede full dial readiness (terminator and policy
// propagation), so the first dial must not assert on a single attempt.
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
