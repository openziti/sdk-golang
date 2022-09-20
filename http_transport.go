package sdk_golang

import (
	"context"
	"crypto/tls"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	cmap "github.com/orcaman/concurrent-map/v2"
	"net"
	"net/http"
	"strings"
)

// NewHttpClient returns a http.Client that can be used exactly as any other http.Client but will route requests
// over a Ziti network using the host name as the Ziti service name. Supplying a tlsConfig is possible to connect
// to HTTPS services, but for it to be successful, the Ziti service name MUST be in the servers URI SANs.
func NewHttpClient(ctx ziti.Context, tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: NewZitiTransport(ctx, tlsConfig),
	}
}

// ZitiTransport wraps the default http.RoundTripper implementation with Ziti edge.Conn pooling
type ZitiTransport struct {
	http.Transport
	connByAddr cmap.ConcurrentMap[edge.Conn]
	Context    ziti.Context
	TlsConfig  *tls.Config
}

// NewZitiTransport returns a new http.Transport that routes HTTP requests and response over a
// Ziti network.
func NewZitiTransport(ctx ziti.Context, clientTlsConfig *tls.Config) *ZitiTransport {
	zitiTransport := &ZitiTransport{
		connByAddr: cmap.New[edge.Conn](),
		TlsConfig:  clientTlsConfig,
		Context:    ctx,
	}

	zitiTransport.Transport = http.Transport{
		DialContext:    zitiTransport.DialContext,
		DialTLSContext: zitiTransport.DialTLSContext,
	}

	return zitiTransport
}

// urlToServiceName removes ports from host names that internal standard GoLang capabilies may have added.
func urlToServiceName(addr string) string {
	return strings.Split(addr, ":")[0]
}

// getConn returns an edge.Conn that can act as a net.Conn, but is pooled by service name.
func (transport *ZitiTransport) getConn(addr string) (edge.Conn, error) {
	var err error
	edgeConn := transport.connByAddr.Upsert(addr, nil, func(_ bool, existingConn edge.Conn, _ edge.Conn) edge.Conn {
		if existingConn == nil || existingConn.IsClosed() {
			var newConn edge.Conn

			serviceName := urlToServiceName(addr)

			if err != nil {
				return nil
			}

			newConn, err = transport.Context.Dial(serviceName)

			return newConn
		}

		return existingConn
	})

	return edgeConn, err
}

func (transport *ZitiTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	edgeConn, err := transport.getConn(addr)

	return edgeConn, err
}

func (transport *ZitiTransport) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	edgeConn, err := transport.getConn(addr)

	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(edgeConn, transport.TlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		if edgeConn != nil {
			_ = edgeConn.Close()
		}
		return nil, err
	}

	return edgeConn, err
}
