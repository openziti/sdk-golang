package edge_apis

import (
	"crypto/x509"
	openapiclient "github.com/go-openapi/runtime/client"
	"github.com/openziti/edge-api/rest_util"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// Components provides the basic shared lower level pieces used to assemble go-swagger/openapi clients. These
// components are interconnected and have references to each other. This struct is used to set, move, and manage
// them as a set.
type Components struct {
	Runtime       *openapiclient.Runtime
	HttpClient    *http.Client
	HttpTransport *http.Transport
	CaPool        *x509.CertPool
}

// NewComponents assembles a new set of components with reasonable production defaults.
func NewComponents(api *url.URL, schemes []string) *Components {
	tlsClientConfig, _ := rest_util.NewTlsConfig()

	httpTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig:       tlsClientConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	jar, _ := cookiejar.New(nil)

	httpClient := &http.Client{
		Transport:     httpTransport,
		CheckRedirect: nil,
		Jar:           jar,
		Timeout:       10 * time.Second,
	}

	apiRuntime := openapiclient.NewWithClient(api.Host, api.Path, schemes, httpClient)

	return &Components{
		Runtime:       apiRuntime,
		HttpClient:    httpClient,
		HttpTransport: httpTransport,
	}
}
