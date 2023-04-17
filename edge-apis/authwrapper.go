// Package edge_apis_2 edge_apis_2 provides a wrapper around the generated Edge Client and Management APIs improve ease
// of use.
package edge_apis

import (
	"github.com/openziti/edge-api/rest_client_api_client"
	clientAuthentication "github.com/openziti/edge-api/rest_client_api_client/authentication"
	"github.com/openziti/edge-api/rest_management_api_client"
	managementAuthentication "github.com/openziti/edge-api/rest_management_api_client/authentication"
	"github.com/openziti/edge-api/rest_model"
	"net/http"
)

// AuthEnabledApi is used as a sentinel interface to detect APIs that support authentication and to work around a golang
// limitation dealing with accessing field of generically typed fields.
type AuthEnabledApi interface {
	//Authenticate will attempt to issue an authentication request using the provided credentials and http client.
	//These function acts as abstraction around the underlying go-swagger generated client and will use the default
	//http client if not provided.
	Authenticate(credentials Credentials, httpClient *http.Client) (*rest_model.CurrentAPISessionDetail, error)
}

// ZitiEdgeManagement is an alias of the go-swagger generated client that allows this package to add additional
// functionality to the alias type to implement the AuthEnabledApi interface.
type ZitiEdgeManagement rest_management_api_client.ZitiEdgeManagement

func (self ZitiEdgeManagement) Authenticate(credentials Credentials, httpClient *http.Client) (*rest_model.CurrentAPISessionDetail, error) {
	params := managementAuthentication.NewAuthenticateParams()
	params.Auth = credentials.Payload()
	params.Method = credentials.Method()

	resp, err := self.Authentication.Authenticate(params, getClientAuthInfoOp(credentials, httpClient))

	if err != nil {
		return nil, err
	}

	return resp.GetPayload().Data, err
}

// ZitiEdgeClient is an alias of the go-swagger generated client that allows this package to add additional
// functionality to the alias type to implement the AuthEnabledApi interface.
type ZitiEdgeClient rest_client_api_client.ZitiEdgeClient

func (self ZitiEdgeClient) Authenticate(credentials Credentials, httpClient *http.Client) (*rest_model.CurrentAPISessionDetail, error) {
	params := clientAuthentication.NewAuthenticateParams()
	params.Auth = credentials.Payload()
	params.Method = credentials.Method()

	resp, err := self.Authentication.Authenticate(params, getClientAuthInfoOp(credentials, httpClient))

	if err != nil {
		return nil, err
	}

	return resp.GetPayload().Data, err
}
