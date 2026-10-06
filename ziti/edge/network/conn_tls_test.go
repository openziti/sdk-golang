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

package network

import (
	"crypto/tls"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// wireChannel hands each message sent on it to deliver, which stands in for the router.
type wireChannel struct {
	NoopTestChannel
	closeNotify chan struct{}

	mu      sync.Mutex
	deliver func(*channel.Message)
}

func newWireChannel() *wireChannel {
	return &wireChannel{closeNotify: make(chan struct{})}
}

func (ch *wireChannel) CloseNotify() <-chan struct{} {
	return ch.closeNotify
}

func (ch *wireChannel) Send(s channel.Sendable) error {
	ch.mu.Lock()
	deliver := ch.deliver
	ch.mu.Unlock()
	msg := s.Msg()
	s.SendListener().NotifyAfterWrite()
	deliver(msg)
	return nil
}

func (ch *wireChannel) setDeliver(f func(*channel.Message)) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.deliver = f
}

// newWiredLegacyConn builds a legacy conn whose messages go out on a wireChannel.
func newWiredLegacyConn(t *testing.T) (*edgeConnLegacy, *wireChannel) {
	closeNotify := make(chan struct{})
	mux := edge.NewChannelConnMapMux[any](nil)
	wire := newWireChannel()
	conn := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{serviceName: "test", closeNotify: closeNotify},
		msgCh:        *edge.NewEdgeMsgChannel(edge.NewSingleSdkChannel(wire), 1),
		mux:          mux,
		readQ:        NewNoopSequencer[*channel.Message](closeNotify, 16),
	}
	conn.initChunkReader()
	require.NoError(t, mux.Add(conn))
	return conn, wire
}

// tlsConnPair is a dialer and a host legacy conn wired to each other, as through a router.
type tlsConnPair struct {
	dialer, host         *edgeConnLegacy
	dialerWire, hostWire *wireChannel
}

func (p *tlsConnPair) close() {
	_ = p.dialer.Close()
	_ = p.host.Close()
}

// newTlsConnPair runs the dial up to the dialer's last flight. Messages from the dialer go through
// dialerToHost, which may hold them back.
func newTlsConnPair(t *testing.T, cliCfg, srvCfg *tls.Config, dialerToHost func(host *edgeConnLegacy, msg *channel.Message)) *tlsConnPair {
	req := require.New(t)
	dialer, dialerWire := newWiredLegacyConn(t)
	host, hostWire := newWiredLegacyConn(t)
	p := &tlsConnPair{dialer: dialer, host: host, dialerWire: dialerWire, hostWire: hostWire}
	hostWire.setDeliver(func(msg *channel.Message) { dialer.AcceptMessage(msg, nil) })
	if dialerToHost == nil {
		dialerToHost = func(host *edgeConnLegacy, msg *channel.Message) { host.AcceptMessage(msg, nil) }
	}
	dialerWire.setDeliver(func(msg *channel.Message) { dialerToHost(host, msg) })

	cli, hello, err := newTlsE2eeClient(cliCfg)
	req.NoError(err)
	srv, flight, err := newTlsE2eeServer(srvCfg, hello)
	req.NoError(err)

	req.NoError(host.installTlsE2ee(srv, host.DataSink()))
	host.primeTlsIfNeeded()

	reply := channel.NewMessage(edge.ContentTypeStateConnected, nil)
	reply.Headers[edge.PublicKeyHeader] = flight
	req.NoError(dialer.establishClientTlsFromReply(cli, reply, dialer.DataSink()))
	dialer.primeTlsIfNeeded()
	return p
}

func readString(t *testing.T, conn *edgeConnLegacy, n int) string {
	t.Helper()
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	require.NoError(t, err)
	return string(buf)
}

// TestTlsConnEcho verifies that data crosses a tls e2ee dialer and host in both directions.
func TestTlsConnEcho(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := newTlsConnPair(t, cliCfg, srvCfg, nil)
	defer p.close()

	_, err := p.dialer.Write([]byte("ping"))
	req.NoError(err)
	req.Equal("ping", readString(t, p.host, 4))

	_, err = p.host.Write([]byte("pong"))
	req.NoError(err)
	req.Equal("pong", readString(t, p.dialer, 4))
}

// TestTlsConnHostWritesFirst verifies that a host can write before it reads: primeTls completes the
// handshake from the dialer's Finished.
func TestTlsConnHostWritesFirst(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := newTlsConnPair(t, cliCfg, srvCfg, nil)
	defer p.close()

	_, err := p.host.Write([]byte("banner"))
	req.NoError(err)
	req.Equal("banner", readString(t, p.dialer, 6))
}

// TestTlsConnHostRejectsDialerCert verifies that a host that rejects the dialer's certificate sends
// the alert and closes the conn, so the dialer learns why instead of writing into a dead circuit.
func TestTlsConnHostRejectsDialerCert(t *testing.T) {
	req := require.New(t)
	hostPki := newTestPki(t)
	srvCfg, err := newE2eeTlsConfig(hostPki.identity(t, "host"), true)
	req.NoError(err)
	// the dialer trusts the host, but its own cert is from a CA the host does not know
	cliCfg, err := newE2eeTlsConfig(newTestPki(t).identityTrusting(t, "dialer", hostPki.pool), false)
	req.NoError(err)

	p := newTlsConnPair(t, cliCfg, srvCfg, nil)
	defer p.close()

	readErr := make(chan error, 1)
	go func() {
		_, err := p.dialer.Read(make([]byte, 16))
		readErr <- err
	}()
	select {
	case err := <-readErr:
		req.ErrorContains(err, "bad certificate")
	case <-time.After(time.Second):
		req.Fail("the dialer never saw the host's alert")
	}
	req.Eventually(p.host.IsClosed, time.Second, 10*time.Millisecond)
}

// TestTlsConnWriteDeadlineDuringHandshake verifies that a write waiting on the handshake gives up at
// the write deadline, including a deadline set while it waits.
func TestTlsConnWriteDeadlineDuringHandshake(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	// the dialer's Finished never reaches the host
	p := newTlsConnPair(t, cliCfg, srvCfg, func(*edgeConnLegacy, *channel.Message) {})
	defer p.close()

	req.NoError(p.host.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)))
	written := make(chan error, 1)
	go func() {
		_, err := p.host.Write([]byte("x"))
		written <- err
	}()
	select {
	case err := <-written:
		req.ErrorIs(err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		req.Fail("the write did not give up at the deadline")
	}

	req.NoError(p.host.SetWriteDeadline(time.Time{}))
	go func() {
		_, err := p.host.Write([]byte("x"))
		written <- err
	}()
	time.Sleep(50 * time.Millisecond)
	req.NoError(p.host.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)))
	select {
	case err := <-written:
		req.ErrorIs(err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		req.Fail("a deadline set during the wait did not end the write")
	}
}

// TestTlsConnReadDeadlineDuringHandshake verifies that a read deadline that passes before the dialer's
// Finished arrives does not stop primeTls, so a host that writes first still completes.
func TestTlsConnReadDeadlineDuringHandshake(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	held := make(chan *channel.Message, 4)
	p := newTlsConnPair(t, cliCfg, srvCfg, func(_ *edgeConnLegacy, msg *channel.Message) {
		held <- msg
	})
	defer p.close()
	req.NoError(p.host.SetReadDeadline(time.Now()))

	go func() {
		time.Sleep(150 * time.Millisecond)
		p.host.AcceptMessage(<-held, nil)
	}()

	written := make(chan error, 1)
	go func() {
		_, err := p.host.Write([]byte("late"))
		written <- err
	}()
	select {
	case err := <-written:
		req.NoError(err)
	case <-time.After(5 * time.Second):
		req.Fail("the host write never completed")
	}
	req.Equal("late", readString(t, p.dialer, 4))
}
