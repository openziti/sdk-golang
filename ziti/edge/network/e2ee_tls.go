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
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"time"

	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/pkg/errors"
)

// tlsE2ee is the CryptoMethodTLS engine. It interoperates with ziti-sdk-c's e2ee_tls.c: TLS
// records travel inside existing edge message fields rather than over a byte stream.
//
//   - dialer: the ClientHello goes in PublicKeyHeader of the Connect message
//   - host: the whole first server flight goes in PublicKeyHeader of the DialSuccess reply
//   - dialer: its last flight is the body of the first Data message on the circuit
//   - data: each Data message body holds the records from one write
//
// crypto/tls only speaks over a net.Conn, so it runs over an in-memory pipe on one goroutine
// (Handshake, then a Read loop). Every call feeds bytes in and waits until that goroutine blocks
// on an empty pipe again, so each call returns everything the input produced, the way the C
// engine's synchronous calls do.
type tlsE2ee struct {
	pipe   *tlsPipe
	conn   *tls.Conn
	server bool

	hsDone chan struct{}
	hsErr  error

	// sendLock keeps drained output in record order when both the writer and the reader flush.
	sendLock sync.Mutex
	sink     io.Writer
}

// tlsPipe is the in-memory net.Conn under the engine. Reads block until input is fed or the
// pipe closes; writes never block. All fields are guarded by mu.
type tlsPipe struct {
	mu   sync.Mutex
	cond *sync.Cond

	in    []byte
	out   []byte
	plain []byte

	// waiting is set while the engine goroutine is blocked in Read on an empty pipe
	waiting bool
	// done is set once the engine goroutine has exited
	done   bool
	closed bool
	err    error
}

func newTlsPipe() *tlsPipe {
	p := &tlsPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *tlsPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.in) == 0 {
		if p.closed {
			return 0, io.EOF
		}
		p.waiting = true
		p.cond.Broadcast()
		p.cond.Wait()
		p.waiting = false
	}
	n := copy(b, p.in)
	p.in = p.in[n:]
	return n, nil
}

func (p *tlsPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	p.out = append(p.out, b...)
	return len(b), nil
}

func (p *tlsPipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cond.Broadcast()
	return nil
}

func (p *tlsPipe) LocalAddr() net.Addr              { return tlsPipeAddr{} }
func (p *tlsPipe) RemoteAddr() net.Addr             { return tlsPipeAddr{} }
func (p *tlsPipe) SetDeadline(time.Time) error      { return nil }
func (p *tlsPipe) SetReadDeadline(time.Time) error  { return nil }
func (p *tlsPipe) SetWriteDeadline(time.Time) error { return nil }

func (p *tlsPipe) appendPlain(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.plain = append(p.plain, b...)
}

// finish records why the engine goroutine exited and wakes any caller waiting in feed.
func (p *tlsPipe) finish(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = true
	p.err = err
	p.cond.Broadcast()
}

func (p *tlsPipe) hasOutput() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.out) > 0
}

func (p *tlsPipe) takeOut() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.out
	p.out = nil
	return out
}

// feed appends input, waits until the engine goroutine is blocked on an empty pipe or has
// exited, and returns the plaintext the input completed. Output stays in the pipe for the
// caller to send.
func (p *tlsPipe) feed(input []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.in = append(p.in, input...)
	p.cond.Broadcast()
	for !p.done && !(p.waiting && len(p.in) == 0) {
		p.cond.Wait()
	}
	plain := p.plain
	p.plain = nil
	// an engine that stopped on EOF still hands over the plaintext it read before stopping
	if p.err != nil && (p.err != io.EOF || len(plain) == 0) {
		return plain, p.err
	}
	return plain, nil
}

type tlsPipeAddr struct{}

func (tlsPipeAddr) Network() string { return "ziti-e2ee" }
func (tlsPipeAddr) String() string  { return "ziti-e2ee" }

// newTlsE2eeClient starts a client handshake and returns the ClientHello.
func newTlsE2eeClient(cfg *tls.Config) (*tlsE2ee, []byte, error) {
	e := newTlsE2ee(cfg, false)
	out, err := e.step(nil)
	if err != nil {
		e.close()
		return nil, nil, err
	}
	if len(out) == 0 {
		e.close()
		return nil, nil, errors.New("tls e2ee: no ClientHello produced")
	}
	return e, out, nil
}

// newTlsE2eeServer feeds the dialer's ClientHello to a new server engine and returns the whole
// first server flight.
func newTlsE2eeServer(cfg *tls.Config, clientHello []byte) (*tlsE2ee, []byte, error) {
	if len(clientHello) == 0 {
		return nil, nil, errors.New("tls e2ee: dialer sent no ClientHello")
	}
	e := newTlsE2ee(cfg, true)
	out, err := e.step(clientHello)
	if err != nil {
		e.close()
		return nil, nil, err
	}
	if len(out) == 0 {
		e.close()
		return nil, nil, errors.New("tls e2ee: no server flight produced")
	}
	if isHelloRetryRequest(out) {
		e.close()
		return nil, nil, errors.New("tls e2ee: dialer offered no key share this host accepts, and this exchange " +
			"cannot carry a HelloRetryRequest (a FIPS host needs a P-256, P-384, or ML-KEM hybrid share)")
	}
	return e, out, nil
}

// helloRetryRequestRandom is the ServerHello.random value that marks a HelloRetryRequest (RFC 8446 4.1.3).
var helloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// isHelloRetryRequest reports whether a server flight opens with a HelloRetryRequest: a handshake
// record whose first message is a ServerHello carrying the HRR random.
func isHelloRetryRequest(flight []byte) bool {
	const (
		recordHandshake  = 22
		msgServerHello   = 2
		randomOffset     = 5 + 4 + 2 // record header, handshake header, legacy_version
		helloRetryMinLen = randomOffset + 32
	)
	return len(flight) >= helloRetryMinLen &&
		flight[0] == recordHandshake &&
		flight[5] == msgServerHello &&
		bytes.Equal(flight[randomOffset:helloRetryMinLen], helloRetryRequestRandom)
}

func newTlsE2ee(cfg *tls.Config, server bool) *tlsE2ee {
	e := &tlsE2ee{
		pipe:   newTlsPipe(),
		server: server,
		hsDone: make(chan struct{}),
	}
	if server {
		e.conn = tls.Server(e.pipe, cfg)
	} else {
		e.conn = tls.Client(e.pipe, cfg)
	}
	go e.run()
	return e
}

func (e *tlsE2ee) run() {
	e.hsErr = e.conn.Handshake()
	close(e.hsDone)
	if e.hsErr != nil {
		e.pipe.finish(errors.Wrap(e.hsErr, "tls e2ee handshake failed"))
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := e.conn.Read(buf)
		if n > 0 {
			e.pipe.appendPlain(buf[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.EOF
			} else {
				err = errors.Wrap(err, "tls e2ee decrypt failed")
			}
			e.pipe.finish(err)
			return
		}
	}
}

// step feeds input to an engine that has no sink yet and returns the handshake output.
func (e *tlsE2ee) step(input []byte) ([]byte, error) {
	if _, err := e.pipe.feed(input); err != nil {
		return nil, err
	}
	return e.pipe.takeOut(), nil
}

func (e *tlsE2ee) handshakeComplete() bool {
	select {
	case <-e.hsDone:
		return e.hsErr == nil
	default:
		return false
	}
}

// setSink installs the writer that carries Data messages to the peer and sends any output
// that is already waiting.
func (e *tlsE2ee) setSink(w io.Writer) error {
	e.sendLock.Lock()
	e.sink = w
	e.sendLock.Unlock()
	return e.flush()
}

// finishClient feeds the host's first flight to the dialer and sends the dialer's last flight,
// which must be the first Data message on the circuit.
func (e *tlsE2ee) finishClient(serverFlight []byte) error {
	if len(serverFlight) == 0 {
		return errors.New("tls e2ee: host sent no handshake flight")
	}
	if _, err := e.pipe.feed(serverFlight); err != nil {
		return err
	}
	return e.flush()
}

// decrypt feeds one Data message body to the engine and returns the plaintext it completed.
// A partial record yields no plaintext and no error. Handshake output the input triggers (a
// TLS 1.2 server Finished, a KeyUpdate reply) is sent to the peer right away.
func (e *tlsE2ee) decrypt(ciphertext []byte) ([]byte, error) {
	plain, err := e.pipe.feed(ciphertext)
	if err != nil {
		return plain, err
	}
	// check before taking sendLock, so a read is not held up behind a write waiting on flow
	// control when there is nothing to send
	if e.pipe.hasOutput() {
		if err = e.flush(); err != nil {
			return plain, err
		}
	}
	return plain, nil
}

// write encrypts data and sends the records from this one write as a single Data message. It
// waits for the handshake to complete first.
func (e *tlsE2ee) write(data []byte) (int, error) {
	<-e.hsDone
	if e.hsErr != nil {
		return 0, errors.Wrap(e.hsErr, "tls e2ee handshake failed")
	}

	e.sendLock.Lock()
	defer e.sendLock.Unlock()
	if e.sink == nil {
		return 0, errors.New("tls e2ee: no data sink")
	}
	if _, err := e.conn.Write(data); err != nil {
		return 0, errors.Wrap(err, "tls e2ee encrypt failed")
	}
	if out := e.pipe.takeOut(); len(out) > 0 {
		if _, err := e.sink.Write(out); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func (e *tlsE2ee) flush() error {
	e.sendLock.Lock()
	defer e.sendLock.Unlock()
	if e.sink == nil || !e.pipe.hasOutput() {
		return nil
	}
	_, err := e.sink.Write(e.pipe.takeOut())
	return err
}

// close stops the engine goroutine. No close_notify is sent: the C engine does not send one
// either, and the edge layer carries the close.
func (e *tlsE2ee) close() {
	_ = e.pipe.Close()
}

// newE2eeTlsConfig builds the TLS config for one side of an e2ee session from the SDK identity.
// Neither side sets a server name. The peer chain is verified against the identity CA bundle
// with any EKU accepted, because identity certs may lack the serverAuth EKU (ziti#4416).
func newE2eeTlsConfig(id identity.Identity, server bool) (*tls.Config, error) {
	if id == nil {
		return nil, errors.New("tls e2ee: no identity")
	}
	cert := id.Cert()
	if cert == nil {
		return nil, errors.New("tls e2ee: identity has no certificate")
	}
	roots := id.CA()
	if roots == nil {
		return nil, errors.New("tls e2ee: identity has no CA bundle")
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// the default verifier requires a hostname and the serverAuth EKU. VerifyConnection
		// does the chain check instead.
		InsecureSkipVerify:     true,
		VerifyConnection:       verifyE2eePeer(roots, server),
		SessionTicketsDisabled: true,
	}

	if server {
		cfg.Certificates = []tls.Certificate{*cert}
		cfg.ClientAuth = tls.RequestClientCert
	} else {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
		// the ClientHello carries a key share for the first curve only. Listing only NIST
		// curves keeps a peer from answering with a HelloRetryRequest, which this message
		// exchange has no room for. The server side keeps the defaults so it can take
		// whatever share the peer offers.
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384}
	}
	return cfg, nil
}

// verifyE2eePeer checks the peer chain against roots. A dialer need not present a certificate,
// but one that does must chain to roots.
func verifyE2eePeer(roots *x509.CertPool, server bool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			if server {
				return nil
			}
			return errors.New("tls e2ee: host presented no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return errors.Wrap(err, "tls e2ee: peer certificate verification failed")
		}
		return nil
	}
}

// checkPeerCryptoMethod fails when the peer names a crypto method other than tls. A missing
// header is accepted: the router strips it, so each side uses its own configured method.
func checkPeerCryptoMethod(val []byte) error {
	if val == nil {
		return nil
	}
	method, err := edge.ParseCryptoMethodHeader(val)
	if err != nil {
		return err
	}
	if method != edge.CryptoMethodTLS {
		return errors.Errorf("crypto method mismatch: peer[%s] != local[%s]", method, edge.CryptoMethodTLS)
	}
	return nil
}
