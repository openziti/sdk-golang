package edge_apis

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/go-openapi/runtime"
	openapiclient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge-api/rest_model"
)

const (
	AuthRequestIdHeader = "auth-request-id"
	TotpRequiredHeader  = "totp-required"
)

// AuthEnabledApi is used as a sentinel interface to detect APIs that support authentication and to work around a golang
// limitation dealing with accessing field of generically typed fields.
type AuthEnabledApi interface {
	//Authenticate will attempt to issue an authentication request using the provided credentials and http client.
	//These functions act as abstraction around the underlying go-swagger generated client and will use the default
	//http client if not provided.
	Authenticate(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error)
	SetUseOidc(bool)
	ListControllers() (*rest_model.ControllersList, error)
	GetClientTransportPool() ClientTransportPool
	SetClientTransportPool(ClientTransportPool)
	RefreshApiSession(apiSession ApiSession, httpClient *http.Client) (ApiSession, error)
}

// BaseClient implements the Client interface specifically for the types specified in the ApiType constraint. It
// provides shared functionality that all ApiType types require.
type BaseClient[A ApiType] struct {
	API            *A
	AuthEnabledApi AuthEnabledApi
	Components
	AuthInfoWriter        runtime.ClientAuthInfoWriter
	ApiSession            atomic.Pointer[ApiSession]
	Credentials           Credentials
	ApiUrls               []*url.URL
	ApiBinding            string
	ApiVersion            string
	Schemes               []string
	onControllerListeners []func([]*url.URL)
}

// Url returns the URL of the currently active controller endpoint.
func (self *BaseClient[A]) Url() url.URL {
	return *self.AuthEnabledApi.GetClientTransportPool().GetActiveTransport().ApiUrl
}

// AddOnControllerUpdateListeners registers a callback that is invoked when the list of
// available controller endpoints changes.
func (self *BaseClient[A]) AddOnControllerUpdateListeners(listener func([]*url.URL)) {
	self.onControllerListeners = append(self.onControllerListeners, listener)
}

// GetCurrentApiSession returns the ApiSession that is being used to authenticate requests.
func (self *BaseClient[A]) GetCurrentApiSession() ApiSession {
	ptr := self.ApiSession.Load()
	if ptr == nil {
		return nil
	}

	return *ptr
}

// SetUseOidc forces the API client to operate in OIDC mode when true, or legacy mode when false.
func (self *BaseClient[A]) SetUseOidc(use bool) {
	v := any(self.API)
	apiType := v.(OidcEnabledApi)
	apiType.SetUseOidc(use)
}

// SetAllowOidcDynamicallyEnabled configures whether the client checks the controller for
// OIDC support and switches modes accordingly.
func (self *BaseClient[A]) SetAllowOidcDynamicallyEnabled(allow bool) {
	v := any(self.API)
	apiType := v.(OidcEnabledApi)
	apiType.SetAllowOidcDynamicallyEnabled(allow)
}

// Authenticate will attempt to use the provided credentials to authenticate via the underlying ApiType. On success
// the API Session details will be returned and the current client will make authenticated requests on future
// calls. On an error the API Session in use will be cleared and subsequent requests will become/continue to be
// made in an unauthenticated fashion.
func (self *BaseClient[A]) Authenticate(credentials Credentials, configTypesOverride []string) (ApiSession, error) {
	self.Credentials = nil
	self.ApiSession.Store(nil)

	if credCaPool := credentials.GetCaPool(); credCaPool != nil {
		self.HttpTransport.TLSClientConfig.RootCAs = credCaPool
	} else {
		self.HttpTransport.TLSClientConfig.RootCAs = self.CaPool
	}

	apiSession, err := self.AuthEnabledApi.Authenticate(credentials, configTypesOverride, self.HttpClient)

	if err != nil {
		return nil, err
	}

	self.Credentials = credentials
	self.ApiSession.Store(&apiSession)

	self.ProcessControllers(self.AuthEnabledApi)

	return apiSession, nil
}

func (self *BaseClient[A]) AuthenticateWithPreviousSession(credentials Credentials, prevApiSession ApiSession) (ApiSession, error) {
	self.Credentials = nil
	self.ApiSession.Store(nil)

	if credCaPool := credentials.GetCaPool(); credCaPool != nil {
		self.HttpTransport.TLSClientConfig.RootCAs = credCaPool
	} else {
		self.HttpTransport.TLSClientConfig.RootCAs = self.CaPool
	}

	refreshedSession, refreshErr := self.AuthEnabledApi.RefreshApiSession(prevApiSession, self.HttpClient)

	if refreshErr != nil {
		return nil, refreshErr
	}

	self.Credentials = credentials
	self.ApiSession.Store(&refreshedSession)

	self.ProcessControllers(self.AuthEnabledApi)

	return refreshedSession, nil
}

// initializeComponents assembles the lower level components necessary for the go-swagger/openapi facilities.
func (self *BaseClient[A]) initializeComponents(config *ApiClientConfig) {
	components := NewComponentsWithConfig(&ComponentsConfig{
		Proxy: config.Proxy,
	})
	components.HttpTransport.TLSClientConfig.RootCAs = config.CaPool
	components.CaPool = config.CaPool

	self.Components = *components
}

// NewRuntime creates an OpenAPI runtime configured for the specified API endpoint.
func NewRuntime(apiUrl *url.URL, schemes []string, httpClient *http.Client) *openapiclient.Runtime {
	return openapiclient.NewWithClient(apiUrl.Host, apiUrl.Path, schemes, httpClient)
}

// AuthenticateRequest implements the openapi runtime.ClientAuthInfoWriter interface from the OpenAPI libraries. It is used
// to authenticate outgoing requests.
func (self *BaseClient[A]) AuthenticateRequest(request runtime.ClientRequest, registry strfmt.Registry) error {
	if self.AuthInfoWriter != nil {
		return self.AuthInfoWriter.AuthenticateRequest(request, registry)
	}

	// do not add auth to authenticating endpoints
	if strings.Contains(request.GetPath(), "/oidc/auth") || strings.Contains(request.GetPath(), "/authenticate") {
		return nil
	}

	currentSessionPtr := self.ApiSession.Load()
	if currentSessionPtr != nil {
		currentSession := *currentSessionPtr

		if currentSession != nil && currentSession.GetToken() != nil {
			if err := currentSession.AuthenticateRequest(request, registry); err != nil {
				return err
			}
		}
	}

	if self.Credentials != nil {
		if err := self.Credentials.AuthenticateRequest(request, registry); err != nil {
			return err
		}
	}

	return nil
}

// ProcessControllers queries the authenticated controller for its list of peer controllers
// and registers them for high-availability failover.
func (self *BaseClient[A]) ProcessControllers(authEnabledApi AuthEnabledApi) {
	list, err := authEnabledApi.ListControllers()

	if err != nil {
		pfxlog.Logger().WithError(err).Debug("error listing controllers, continuing with 1 default configured controller")
		return
	}

	if list == nil || len(*list) <= 1 {
		pfxlog.Logger().Debug("no additional controllers reported, continuing with 1 default configured controller")
		return
	}

	//look for matching api binding and versions
	for _, controller := range *list {
		apis := controller.APIAddresses[self.ApiBinding]

		for _, apiAddr := range apis {
			if apiAddr.Version == self.ApiVersion {
				apiUrl, parseErr := url.Parse(apiAddr.URL)
				if parseErr == nil {
					self.AuthEnabledApi.GetClientTransportPool().Add(apiUrl, NewRuntime(apiUrl, self.Schemes, self.HttpClient))
				}
			}
		}
	}

	apis := self.AuthEnabledApi.GetClientTransportPool().GetApiUrls()
	for _, listener := range self.onControllerListeners {
		listener(apis)
	}
}
