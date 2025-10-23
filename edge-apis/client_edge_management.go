package edge_apis

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"sync"

	"github.com/openziti/edge-api/rest_management_api_client"
	manAuth "github.com/openziti/edge-api/rest_management_api_client/authentication"
	manControllers "github.com/openziti/edge-api/rest_management_api_client/controllers"
	manCurApiSession "github.com/openziti/edge-api/rest_management_api_client/current_api_session"
	manInfo "github.com/openziti/edge-api/rest_management_api_client/informational"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
	"github.com/openziti/foundation/v2/stringz"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ManagementApiClient provides the ability to authenticate and interact with the Edge Management API.
type ManagementApiClient struct {
	BaseClient[ZitiEdgeManagement]
}

// NewManagementApiClient will assemble an ManagementApiClient. The apiUrl should be the full URL
// to the Edge Management API (e.g. `https://example.com/edge/management/v1`).
//
// The `caPool` argument should be a list of trusted root CAs. If provided as `nil` here unauthenticated requests
// will use the system certificate pool. If authentication occurs, and a certificate pool is set on the Credentials
// the certificate pool from the Credentials will be used from that point forward. Credentials implementations
// based on an identity.Identity are likely to provide a certificate pool.
//
// For OpenZiti instances not using publicly signed certificates, `ziti.GetControllerWellKnownCaPool()` can be used
// to obtain and verify the target controllers CAs. Tools should allow users to verify and accept new controllers
// that have not been verified from an outside secret (such as an enrollment token).
func NewManagementApiClient(apiUrls []*url.URL, caPool *x509.CertPool, totpCallback func(chan string)) *ManagementApiClient {
	return NewManagementApiClientWithConfig(&ApiClientConfig{
		ApiUrls:      apiUrls,
		CaPool:       caPool,
		TotpCallback: totpCallback,
		Proxy:        http.ProxyFromEnvironment,
	})
}

// NewManagementApiClientWithConfig creates a Management API client using the provided configuration.
func NewManagementApiClientWithConfig(config *ApiClientConfig) *ManagementApiClient {
	ret := &ManagementApiClient{}
	ret.Schemes = rest_management_api_client.DefaultSchemes
	ret.ApiBinding = "edge-management"
	ret.ApiVersion = "v1"
	ret.ApiUrls = config.ApiUrls
	ret.initializeComponents(config)

	transportPool := NewClientTransportPoolRandom()

	for _, apiUrl := range config.ApiUrls {
		newRuntime := NewRuntime(apiUrl, ret.Schemes, ret.HttpClient)
		newRuntime.DefaultAuthentication = ret
		transportPool.Add(apiUrl, newRuntime)
	}

	newApi := rest_management_api_client.New(transportPool, nil)
	api := ZitiEdgeManagement{
		ZitiEdgeManagement:  newApi,
		TotpCallback:        config.TotpCallback,
		ClientTransportPool: transportPool,
	}

	ret.API = &api
	ret.AuthEnabledApi = &api

	return ret
}

var _ AuthEnabledApi = (*ZitiEdgeManagement)(nil)

// ZitiEdgeManagement is an alias of the go-swagger generated client that allows this package to add additional
// functionality to the alias type to implement the AuthEnabledApi interface.
type ZitiEdgeManagement struct {
	*rest_management_api_client.ZitiEdgeManagement
	// useOidc tracks if OIDC auth should be used
	useOidc bool

	// useOidcExplicitlySet signals if useOidc was set from an external caller and should be used as is
	useOidcExplicitlySet bool

	// oidcDynamicallyEnabled will cause the client to check the controller for OIDC support and use if possible as long as useOidc was not explicitly set
	oidcDynamicallyEnabled bool //currently defaults false till HA release

	versionOnce sync.Once
	versionInfo *rest_model.Version

	TotpCallback        func(chan string)
	ClientTransportPool ClientTransportPool
}

func (self *ZitiEdgeManagement) SetClientTransportPool(transportPool ClientTransportPool) {
	self.ClientTransportPool = transportPool
}

func (self *ZitiEdgeManagement) GetClientTransportPool() ClientTransportPool {
	return self.ClientTransportPool
}

func (self *ZitiEdgeManagement) ListControllers() (*rest_model.ControllersList, error) {
	params := manControllers.NewListControllersParams()
	resp, err := self.Controllers.ListControllers(params, nil)
	if err != nil {
		return nil, err
	}

	return &resp.GetPayload().Data, nil
}

func (self *ZitiEdgeManagement) Authenticate(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	self.versionOnce.Do(func() {
		if self.useOidcExplicitlySet {
			return
		}

		if self.oidcDynamicallyEnabled {
			versionParams := manInfo.NewListVersionParams()

			versionResp, _ := self.Informational.ListVersion(versionParams)

			if versionResp != nil {
				self.versionInfo = versionResp.Payload.Data
				self.useOidc = stringz.Contains(self.versionInfo.Capabilities, string(rest_model.CapabilitiesOIDCAUTH))
			}
		} else {
			self.useOidc = false
		}
	})

	if self.useOidc {
		return self.oidcAuth(credentials, configTypes, httpClient)
	}

	return self.legacyAuth(credentials, configTypes, httpClient)
}

func (self *ZitiEdgeManagement) legacyAuth(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	params := manAuth.NewAuthenticateParams()
	params.Auth = credentials.Payload()
	params.Method = credentials.Method()
	params.Auth.ConfigTypes = append(params.Auth.ConfigTypes, configTypes...)

	certs := credentials.TlsCerts()
	if len(certs) != 0 {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.Certificates = certs
			transport.CloseIdleConnections()
		}
	}

	resp, err := self.Authentication.Authenticate(params, getClientAuthInfoOp(credentials, httpClient))

	if err != nil {
		return nil, err
	}

	return &ApiSessionLegacy{
		Detail:         resp.GetPayload().Data,
		RequestHeaders: credentials.GetRequestHeaders()}, err
}

func (self *ZitiEdgeManagement) oidcAuth(credentials Credentials, configTypeOverrides []string, httpClient *http.Client) (ApiSession, error) {
	return oidcAuth(self.ClientTransportPool, credentials, configTypeOverrides, httpClient, self.TotpCallback)
}

func (self *ZitiEdgeManagement) SetUseOidc(use bool) {
	self.useOidcExplicitlySet = true
	self.useOidc = use
}

func (self *ZitiEdgeManagement) SetAllowOidcDynamicallyEnabled(allow bool) {
	self.oidcDynamicallyEnabled = allow
}

func (self *ZitiEdgeManagement) RefreshApiSession(apiSession ApiSession, httpClient *http.Client) (ApiSession, error) {
	switch s := apiSession.(type) {
	case *ApiSessionLegacy:
		params := manCurApiSession.NewGetCurrentAPISessionParams()
		newApiSessionDetail, err := self.CurrentAPISession.GetCurrentAPISession(params, s)

		if err != nil {
			return nil, rest_util.WrapErr(err)
		}

		newApiSession := &ApiSessionLegacy{
			Detail:         newApiSessionDetail.Payload.Data,
			RequestHeaders: apiSession.GetRequestHeaders(),
		}

		return newApiSession, nil
	case *ApiSessionOidc:
		tokens, err := self.ExchangeTokens(s.OidcTokens, httpClient)

		if err != nil {
			return nil, err
		}

		return &ApiSessionOidc{
			OidcTokens:     tokens,
			RequestHeaders: apiSession.GetRequestHeaders(),
		}, nil
	}

	return nil, errors.New("api session is an unknown type")
}

func (self *ZitiEdgeManagement) ExchangeTokens(curTokens *oidc.Tokens[*oidc.IDTokenClaims], httpClient *http.Client) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return exchangeTokens(self.ClientTransportPool, curTokens, httpClient)
}
