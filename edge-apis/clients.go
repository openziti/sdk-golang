/*
	Copyright 2019 NetFoundry Inc.

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

package edge_apis

import (
	"crypto/x509"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/openziti/edge-api/rest_client_api_client"
	"github.com/openziti/edge-api/rest_management_api_client"
	"github.com/pkg/errors"
	"net/url"
	"sync/atomic"
)

// ApiType is an interface constraint for generics. The underlying go-swagger types only have fields, which are
// insufficient to attempt to make a generic type from. Instead, this constraint is used that points at the
// aliased types.
type ApiType interface {
	ZitiEdgeManagement | ZitiEdgeClient
}

// BaseClient implements the Client interface specifically for the types specified in the ApiType constraint. It
// provides shared functionality that all ApiType types require.
type BaseClient[A ApiType] struct {
	API *A
	Components
	AuthInfoWriter runtime.ClientAuthInfoWriter
	ApiSession     atomic.Pointer[ApiSession]
	Credentials    Credentials
}

// GetCurrentApiSession returns the ApiSession that is being used to authenticate requests.
func (self *BaseClient[A]) GetCurrentApiSession() *ApiSession {
	return self.ApiSession.Load()
}

// Authenticate will attempt to use the provided credentials to authenticate via the underlying ApiType. On success
// the API Session details will be returned and the current client will make authenticated requests on future
// calls. On an error the API Session in use will be cleared and subsequent requests will become/continue to be
// made in an unauthenticated fashion.
func (self *BaseClient[A]) Authenticate(credentials Credentials, configTypes []string) (*ApiSession, error) {
	//casting to `any` works around golang error that happens when type asserting a generic typed field
	myAny := any(self.API)
	if a, ok := myAny.(AuthEnabledApi); ok {
		self.Credentials = nil
		self.ApiSession.Store(nil)

		if credCaPool := credentials.GetCaPool(); credCaPool != nil {
			self.HttpTransport.TLSClientConfig.RootCAs = credCaPool
		} else {
			self.HttpTransport.TLSClientConfig.RootCAs = self.Components.CaPool
		}

		apiSession, err := a.Authenticate(credentials, configTypes, self.HttpClient)

		if err != nil {
			return nil, err
		}

		self.Credentials = credentials
		self.ApiSession.Store(apiSession)

		self.Runtime.DefaultAuthentication = runtime.ClientAuthInfoWriterFunc(func(request runtime.ClientRequest, registry strfmt.Registry) error {
			if currentSession := self.ApiSession.Load(); currentSession != nil && currentSession.Token != nil {
				if err := currentSession.AuthenticateRequest(request, registry); err != nil {
					return err
				}
			}

			if self.Credentials != nil {
				if err := self.Credentials.AuthenticateRequest(request, registry); err != nil {
					return err
				}
			}

			return nil
		})

		return apiSession, nil
	}
	return nil, errors.New("authentication not supported")
}

// initializeComponents assembles the lower level components necessary for the go-swagger/openapi facilities.
func (self *BaseClient[A]) initializeComponents(apiUrl *url.URL, schemes []string, authInfoWriter runtime.ClientAuthInfoWriter, caPool *x509.CertPool) {
	components := NewComponents(apiUrl, schemes)
	components.HttpTransport.TLSClientConfig.RootCAs = caPool
	components.Runtime.DefaultAuthentication = authInfoWriter
	components.CaPool = caPool
	self.Components = *components
}

// AuthenticateRequest implements the openapi runtime.ClientAuthInfoWriter interface from the OpenAPI libraries. It is used
// to authenticate outgoing requests.
func (self *BaseClient[A]) AuthenticateRequest(request runtime.ClientRequest, registry strfmt.Registry) error {
	if self.AuthInfoWriter != nil {
		return self.AuthInfoWriter.AuthenticateRequest(request, registry)
	}
	return nil
}

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
func NewManagementApiClient(apiUrl *url.URL, caPool *x509.CertPool, totpCallback func(chan string)) *ManagementApiClient {
	ret := &ManagementApiClient{}

	ret.initializeComponents(apiUrl, rest_management_api_client.DefaultSchemes, ret, caPool)

	newApi := rest_management_api_client.New(ret.Components.Runtime, nil)
	api := ZitiEdgeManagement{
		ZitiEdgeManagement: newApi,
		apiUrl:             apiUrl,
		TotpCallback:       totpCallback,
	}

	ret.API = &api

	return ret
}

type ClientApiClient struct {
	BaseClient[ZitiEdgeClient]
}

// NewClientApiClient will assemble a  ClientApiClient. The apiUrl should be the full URL
// to the Edge Client API (e.g. `https://example.com/edge/client/v1`).
//
// The `caPool` argument should be a list of trusted root CAs. If provided as `nil` here unauthenticated requests
// will use the system certificate pool. If authentication occurs, and a certificate pool is set on the Credentials
// the certificate pool from the Credentials will be used from that point forward. Credentials implementations
// based on an identity.Identity are likely to provide a certificate pool.
//
// For OpenZiti instances not using publicly signed certificates, `ziti.GetControllerWellKnownCaPool()` can be used
// to obtain and verify the target controllers CAs. Tools should allow users to verify and accept new controllers
// that have not been verified from an outside secret (such as an enrollment token).
func NewClientApiClient(apiUrl *url.URL, caPool *x509.CertPool, totpCallback func(chan string)) *ClientApiClient {
	ret := &ClientApiClient{}

	ret.initializeComponents(apiUrl, rest_client_api_client.DefaultSchemes, ret, caPool)

	newApi := rest_client_api_client.New(ret.Components.Runtime, nil)
	api := ZitiEdgeClient{
		ZitiEdgeClient: newApi,
		apiUrl:         apiUrl,
		TotpCallback:   totpCallback,
	}
	ret.API = &api

	return ret
}
