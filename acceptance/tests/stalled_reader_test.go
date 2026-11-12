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
	"sync"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

const (
	stalledAppData = "stalled"

	// stalledPayloadSize is sent in stalledWriteSize writes so it reaches the host as many
	// messages: the read queue limit is per conn, so another conn only waits once more of the
	// stalled conn's messages arrive ahead of its own.
	stalledPayloadSize = 1024 * 1024
	stalledWriteSize   = 16 * 1024
)

// stallingServer hosts a service without SDK flow control, so the router delivers every
// accepted conn's data on the host's one router connection. The conn dialed with
// stalledAppData isn't read until releaseStalled, then is read in full and its data sent on
// stalledData. Every other conn echoes what it reads and sends it on received.
type stallingServer struct {
	release     chan struct{}
	releaseOnce sync.Once
	received    chan string
	stalledData chan []byte
}

func startStallingServer(tb testing.TB, hostCtx ziti.Context, service string) *stallingServer {
	tb.Helper()
	sdkFlowControl := false
	listener, err := hostCtx.ListenWithOptions(service, &ziti.ListenOptions{
		WaitForNEstablishedListeners: 1,
		ConnectTimeout:               30 * time.Second,
		SdkFlowControl:               &sdkFlowControl,
	})
	require.NoError(tb, err)

	s := &stallingServer{
		release:     make(chan struct{}),
		received:    make(chan string, 16),
		stalledData: make(chan []byte, 1),
	}
	tb.Cleanup(func() {
		s.releaseStalled()
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.AcceptEdge()
			if err != nil {
				return
			}
			if string(conn.GetAppData()) == stalledAppData {
				go s.readWhenReleased(conn)
			} else {
				go s.echo(conn)
			}
		}
	}()
	return s
}

func (s *stallingServer) releaseStalled() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *stallingServer) readWhenReleased(conn edge.Conn) {
	defer func() { _ = conn.Close() }()
	<-s.release
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	data := make([]byte, stalledPayloadSize)
	n, _ := io.ReadFull(conn, data)
	s.stalledData <- data[:n]
}

func (s *stallingServer) echo(conn edge.Conn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			s.received <- string(buf[:n])
			_, _ = conn.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// requireReceived waits up to timeout for the server's echo conn to receive expected.
func (s *stallingServer) requireReceived(tb testing.TB, expected string, timeout time.Duration, msg string) {
	tb.Helper()
	select {
	case got := <-s.received:
		require.Equal(tb, expected, got)
	case <-time.After(timeout):
		tb.Fatal(msg)
	}
}

// requireStalledDataIntact releases the stalled conn's reader and checks it gets every byte sent,
// in order.
func (s *stallingServer) requireStalledDataIntact(tb testing.TB, sent []byte) {
	tb.Helper()
	s.releaseStalled()
	select {
	case got := <-s.stalledData:
		require.Equal(tb, len(sent), len(got), "the stalled conn's reader got a short read")
		require.True(tb, bytes.Equal(sent, got), "the stalled conn's data arrived corrupted or out of order")
	case <-time.After(60 * time.Second):
		tb.Fatal("the stalled conn's reader never finished reading")
	}
}

// startStallTest hosts a stalling server on a context built with hostOptions and dials it twice
// from one client: a conn whose host-side reader stalls, and an echo conn. Both are dialed
// before any data flows, so each is accepted before the stall begins.
func startStallTest(t *testing.T, hostOptions *ziti.Options) (stalled, echo edge.Conn, server *stallingServer) {
	t.Helper()
	h := shared // shared test harness, set up in main_test.go
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	clientID := h.CreateIdentity(t, "client")
	svc := h.CreateService(t, "stall")
	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, clientID)
	h.GrantRouterAccess(t, r, hostID, clientID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContextWithOptions(t, hostID, hostOptions)
	server = startStallingServer(t, hostCtx, svc.Name())

	clientCtx := h.NewSdkContext(t, clientID)
	stalled = dialWithOptionsRetry(t, clientCtx, svc.Name(), &ziti.DialOptions{
		ConnectTimeout: 30 * time.Second,
		AppData:        []byte(stalledAppData),
	})
	t.Cleanup(func() { _ = stalled.Close() })
	echo = dialWithOptionsRetry(t, clientCtx, svc.Name(), &ziti.DialOptions{ConnectTimeout: 30 * time.Second})
	t.Cleanup(func() { _ = echo.Close() })
	return stalled, echo, server
}

// writeStalledPayload sends stalledPayloadSize bytes on conn, whose host-side reader is stalled,
// and returns them.
func writeStalledPayload(tb testing.TB, conn edge.Conn) []byte {
	tb.Helper()
	payload := make([]byte, stalledPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	done := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); off += stalledWriteSize {
			if _, err := conn.Write(payload[off : off+stalledWriteSize]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		require.NoError(tb, err)
	case <-time.After(30 * time.Second):
		tb.Fatal("writing to the stalled conn didn't finish; the data never left the client")
	}
	return payload
}

// Test_StalledReader_DoesNotBlockOtherConns checks that a host without SDK flow control keeps
// receiving on its other conns while one conn's reader has stopped with less than
// Options.RxBufferSizeWithoutSdkFlowControl (4 MiB by default) waiting, and that the stalled conn
// still gets all its data, in order, once it reads.
func Test_StalledReader_DoesNotBlockOtherConns(t *testing.T) {
	stalled, echo, server := startStallTest(t, nil)

	sent := writeStalledPayload(t, stalled)

	_, err := echo.Write([]byte("ping"))
	require.NoError(t, err)
	server.requireReceived(t, "ping", 30*time.Second,
		"another conn's data never reached the host while one conn's reader was stalled below its read buffer size")

	server.requireStalledDataIntact(t, sent)
}

// Test_StalledReader_PastRxBufferSizeBlocksOtherConns checks that the host honors
// Options.RxBufferSizeWithoutSdkFlowControl: once a stalled conn has more than that waiting, the
// host's other conns on the same router connection receive nothing until the stalled reader
// catches up, and then everything is delivered.
func Test_StalledReader_PastRxBufferSizeBlocksOtherConns(t *testing.T) {
	options := *ziti.DefaultOptions
	options.RxBufferSizeWithoutSdkFlowControl = 64 * 1024
	stalled, echo, server := startStallTest(t, &options)

	sent := writeStalledPayload(t, stalled)

	_, err := echo.Write([]byte("ping"))
	require.NoError(t, err)
	select {
	case got := <-server.received:
		t.Fatalf("another conn received %q although the stalled conn had more than the host's read buffer size waiting", got)
	case <-time.After(3 * time.Second):
	}

	server.requireStalledDataIntact(t, sent)
	server.requireReceived(t, "ping", 30*time.Second,
		"another conn's data never reached the host after the stalled reader caught up")
}
