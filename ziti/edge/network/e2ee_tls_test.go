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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// e2eeMaxMsgOverhead is ziti-sdk-c's E2EE_MAX_MSG_OVERHEAD: the C sender sizes a Data message
// body as plaintext + this much, so records from one write must fit in it.
const e2eeMaxMsgOverhead = 1024

type testPki struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
}

func newTestPki(t *testing.T) *testPki {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2ee-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testPki{caCert: cert, caKey: key, pool: pool}
}

// identity issues a leaf with only the clientAuth EKU, like a ziti identity cert before ziti#4416.
func (p *testPki) identity(t *testing.T, name string) identity.Identity {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return identity.NewClientTokenIdentityWithPool([]*x509.Certificate{cert, p.caCert}, key, p.pool)
}

// recordSink stands in for the edge conn's data sink: each Write is one Data message.
type recordSink struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (s *recordSink) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, append([]byte(nil), b...))
	return len(b), nil
}

func (s *recordSink) take() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	msgs := s.msgs
	s.msgs = nil
	return msgs
}

type tlsPair struct {
	cli, srv         *tlsE2ee
	cliSink, srvSink *recordSink
}

func (p *tlsPair) close() {
	p.cli.close()
	p.srv.close()
}

// startPair runs the message exchange up to the dialer sending its last flight, which is left
// in cliSink as the first Data message.
func startPair(t *testing.T, cliCfg, srvCfg *tls.Config) *tlsPair {
	cli, hello, err := newTlsE2eeClient(cliCfg)
	require.NoError(t, err)
	srv, flight, err := newTlsE2eeServer(srvCfg, hello)
	require.NoError(t, err)

	p := &tlsPair{cli: cli, srv: srv, cliSink: &recordSink{}, srvSink: &recordSink{}}
	require.NoError(t, srv.setSink(p.srvSink))
	require.NoError(t, cli.setSink(p.cliSink))
	require.NoError(t, cli.finishClient(flight))
	return p
}

func testConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	pki := newTestPki(t)
	cliCfg, err := newE2eeTlsConfig(pki.identity(t, "dialer"), false)
	require.NoError(t, err)
	srvCfg, err := newE2eeTlsConfig(pki.identity(t, "host"), true)
	require.NoError(t, err)
	return cliCfg, srvCfg
}

func decryptAll(t *testing.T, e *tlsE2ee, msgs [][]byte) []byte {
	var out []byte
	for _, m := range msgs {
		plain, err := e.decrypt(m)
		require.NoError(t, err)
		out = append(out, plain...)
	}
	return out
}

func TestTlsE2eeHandshakeAndData(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := startPair(t, cliCfg, srvCfg)
	defer p.close()

	req.True(p.cli.handshakeComplete(), "a TLS 1.3 dialer is done after the host's first flight")
	req.False(p.srv.handshakeComplete())

	finished := p.cliSink.take()
	req.Len(finished, 1, "the dialer's last flight is one Data message")
	req.Empty(decryptAll(t, p.srv, finished))
	req.True(p.srv.handshakeComplete())
	req.Equal(tls.VersionTLS13, int(p.srv.conn.ConnectionState().Version))
	req.Empty(p.srvSink.take(), "a TLS 1.3 host sends nothing more after the dialer's Finished")

	_, err := p.cli.write([]byte("hello from the dialer"))
	req.NoError(err)
	req.Equal("hello from the dialer", string(decryptAll(t, p.srv, p.cliSink.take())))

	_, err = p.srv.write([]byte("hello from the host"))
	req.NoError(err)
	req.Equal("hello from the host", string(decryptAll(t, p.cli, p.srvSink.take())))
}

func TestTlsE2eeTls12(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	cliCfg.MaxVersion = tls.VersionTLS12
	p := startPair(t, cliCfg, srvCfg)
	defer p.close()

	req.False(p.cli.handshakeComplete(), "a TLS 1.2 dialer waits for the host's Finished")
	req.Empty(decryptAll(t, p.srv, p.cliSink.take()))
	req.True(p.srv.handshakeComplete())
	req.Equal(tls.VersionTLS12, int(p.srv.conn.ConnectionState().Version))

	// the host sends its Finished at once rather than holding it for its first write
	srvFinished := p.srvSink.take()
	req.Len(srvFinished, 1)
	req.Empty(decryptAll(t, p.cli, srvFinished))
	req.True(p.cli.handshakeComplete())

	_, err := p.cli.write([]byte("ping"))
	req.NoError(err)
	req.Equal("ping", string(decryptAll(t, p.srv, p.cliSink.take())))
	_, err = p.srv.write([]byte("pong"))
	req.NoError(err)
	req.Equal("pong", string(decryptAll(t, p.cli, p.srvSink.take())))
}

func TestTlsE2eeFragmentedRecords(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := startPair(t, cliCfg, srvCfg)
	defer p.close()

	// the dialer's Finished, one byte per message
	for _, m := range p.cliSink.take() {
		for i := range m {
			plain, err := p.srv.decrypt(m[i : i+1])
			req.NoError(err)
			req.Empty(plain)
		}
	}
	req.True(p.srv.handshakeComplete())

	// two writes, cut at points that straddle the record boundary between them
	_, err := p.cli.write([]byte("first message"))
	req.NoError(err)
	_, err = p.cli.write([]byte("second message"))
	req.NoError(err)
	stream := bytes.Join(p.cliSink.take(), nil)

	var got []byte
	for _, cut := range [][2]int{{0, 3}, {3, 20}, {20, 41}, {41, len(stream)}} {
		plain, err := p.srv.decrypt(stream[cut[0]:cut[1]])
		req.NoError(err, "a partial record is not an error")
		got = append(got, plain...)
	}
	req.Equal("first messagesecond message", string(got))
}

func TestTlsE2eeLargePayload(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := startPair(t, cliCfg, srvCfg)
	defer p.close()
	decryptAll(t, p.srv, p.cliSink.take())

	// larger than a TLS record, and than the C SDK's MAX_CHAIN_LEN
	big := make([]byte, 100*1024+7)
	_, err := rand.Read(big)
	req.NoError(err)

	_, err = p.cli.write(big)
	req.NoError(err)
	msgs := p.cliSink.take()
	req.Len(msgs, 1, "the records from one write go in one Data message")
	req.LessOrEqual(len(msgs[0]), len(big)+e2eeMaxMsgOverhead, "a C receiver sizes by the C sender's overhead")
	req.Equal(big, decryptAll(t, p.srv, msgs))

	_, err = p.srv.write(big)
	req.NoError(err)
	req.Equal(big, decryptAll(t, p.cli, p.srvSink.take()))
}

func TestTlsE2eeHandshakeWithData(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := startPair(t, cliCfg, srvCfg)
	defer p.close()

	finished := p.cliSink.take()
	_, err := p.cli.write([]byte("early data"))
	req.NoError(err)
	data := p.cliSink.take()

	// the dialer's Finished and its first data arrive in one buffer (ziti-sdk-c e01e1e4)
	plain, err := p.srv.decrypt(bytes.Join(append(finished, data...), nil))
	req.NoError(err)
	req.True(p.srv.handshakeComplete())
	req.Equal("early data", string(plain))
}

func TestTlsE2eeUntrustedHost(t *testing.T) {
	req := require.New(t)
	cliCfg, _ := testConfigs(t)
	_, otherSrvCfg := testConfigs(t)

	cli, hello, err := newTlsE2eeClient(cliCfg)
	req.NoError(err)
	defer cli.close()
	srv, flight, err := newTlsE2eeServer(otherSrvCfg, hello)
	req.NoError(err)
	defer srv.close()

	req.NoError(cli.setSink(&recordSink{}))
	req.Error(cli.finishClient(flight), "a host cert from another CA must fail verification")
	req.False(cli.handshakeComplete())
	_, err = cli.write([]byte("x"))
	req.Error(err)
}

func TestTlsE2eePeerCryptoMethod(t *testing.T) {
	req := require.New(t)
	req.NoError(checkPeerCryptoMethod(nil))
	req.NoError(checkPeerCryptoMethod([]byte("tls")))
	req.NoError(checkPeerCryptoMethod([]byte{byte(edge.CryptoMethodTLS)}))
	req.Error(checkPeerCryptoMethod([]byte("libsodium")))
	req.Error(checkPeerCryptoMethod([]byte{byte(edge.CryptoMethodLibsodium)}))
	req.Error(checkPeerCryptoMethod([]byte("none")))
}

// A host that writes before the application reads must not wait forever: primeTls pulls the
// dialer's Finished from the chunk source so the handshake completes.
func TestTlsE2eeHostWritesFirst(t *testing.T) {
	req := require.New(t)
	cliCfg, srvCfg := testConfigs(t)
	p := startPair(t, cliCfg, srvCfg)
	defer p.close()

	chunks := make(chan []byte, 16)
	source := func() ([]byte, uint32, error) {
		c, ok := <-chunks
		if !ok {
			return nil, 0, io.EOF
		}
		return c, 0, nil
	}
	reader := newEdgeChunkReader(source, func() *logrus.Entry { return logrus.NewEntry(logrus.StandardLogger()) })
	reader.SetTls(p.srv)
	go reader.primeTls()

	written := make(chan error, 1)
	go func() {
		_, err := p.srv.write([]byte("server speaks first"))
		written <- err
	}()

	select {
	case <-written:
		req.Fail("the host wrote before the handshake completed")
	case <-time.After(50 * time.Millisecond):
	}

	_, err := p.cli.write([]byte("dialer data"))
	req.NoError(err)
	for _, m := range p.cliSink.take() {
		chunks <- m
	}

	select {
	case err := <-written:
		req.NoError(err)
	case <-time.After(5 * time.Second):
		req.Fail("the host write never completed")
	}
	req.Equal("server speaks first", string(decryptAll(t, p.cli, p.srvSink.take())))

	// data that arrived during priming is kept for the application's first Read
	buf := make([]byte, 64)
	n, err := reader.Read(buf)
	req.NoError(err)
	req.Equal("dialer data", string(buf[:n]))
	close(chunks)
}
