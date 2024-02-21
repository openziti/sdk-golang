// Package edge_apis_2 edge_apis_2 provides a wrapper around the generated Edge Client and Management APIs improve ease
// of use.
package edge_apis

import (
	"encoding/json"
	"fmt"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-resty/resty/v2"
	"github.com/openziti/edge-api/rest_client_api_client"
	clientAuth "github.com/openziti/edge-api/rest_client_api_client/authentication"
	clientApiSession "github.com/openziti/edge-api/rest_client_api_client/current_api_session"
	clientInfo "github.com/openziti/edge-api/rest_client_api_client/informational"
	"github.com/openziti/edge-api/rest_management_api_client"
	manAuth "github.com/openziti/edge-api/rest_management_api_client/authentication"
	manCurApiSession "github.com/openziti/edge-api/rest_management_api_client/current_api_session"
	manInfo "github.com/openziti/edge-api/rest_management_api_client/informational"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
	"github.com/openziti/foundation/v2/errorz"
	"github.com/openziti/foundation/v2/stringz"
	"github.com/pkg/errors"
	"github.com/zitadel/oidc/v2/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
}

type ApiSession interface {
	//GetAccessHeader returns the HTTP header name and value that should be used to represent this ApiSession
	GetAccessHeader() (string, string)

	//AuthenticateRequest fulfills the interface defined by the OpenAPI libraries to authenticate client HTTP requests
	AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error

	//GetToken returns the ApiSessions' token bytes
	GetToken() []byte

	//GetExpiresAt returns the time when the ApiSession will expire.
	GetExpiresAt() *time.Time

	//GetAuthQueries returns a list of authentication queries the ApiSession is subjected to
	GetAuthQueries() rest_model.AuthQueryList

	//GetIdentityName returns the name of the authenticating identity
	GetIdentityName() string

	//GetIdentityId returns the id of the authenticating identity
	GetIdentityId() string

	//GetId returns the id of the ApiSession
	GetId() string
}

var _ ApiSession = (*ApiSessionLegacy)(nil)
var _ ApiSession = (*ApiSessionOidc)(nil)

// ApiSessionLegacy represents OpenZiti's original authentication API Session Detail, supplied in the `zt-session` header.
// It has been supplanted by OIDC authentication represented by ApiSessionOidc.
type ApiSessionLegacy struct {
	Detail *rest_model.CurrentAPISessionDetail
}

func (a *ApiSessionLegacy) GetId() string {
	return stringz.OrEmpty(a.Detail.ID)
}

func (a *ApiSessionLegacy) GetIdentityName() string {
	return a.Detail.Identity.Name
}

func (a *ApiSessionLegacy) GetIdentityId() string {
	return stringz.OrEmpty(a.Detail.IdentityID)
}

// GetAccessHeader returns the header and header token value should be used for authentication requests
func (a *ApiSessionLegacy) GetAccessHeader() (string, string) {
	if a.Detail != nil && a.Detail.Token != nil {
		return "zt-session", *a.Detail.Token
	}

	return "", ""
}

func (a *ApiSessionLegacy) AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error {
	if a == nil {
		return errors.New("api session is nil")
	}

	header, val := a.GetAccessHeader()

	err := request.SetHeaderParam(header, val)
	if err != nil {
		return err
	}

	return nil
}

func (a *ApiSessionLegacy) GetToken() []byte {
	if a.Detail != nil && a.Detail.Token != nil {
		return []byte(*a.Detail.Token)
	}

	return nil
}

func (a *ApiSessionLegacy) GetAuthQueries() rest_model.AuthQueryList {
	return a.Detail.AuthQueries
}

func (a *ApiSessionLegacy) GetExpiresAt() *time.Time {
	if a.Detail != nil {
		return (*time.Time)(a.Detail.ExpiresAt)
	}

	return nil
}

// ApiSessionOidc represents an authenticated session backed by OIDC tokens.
type ApiSessionOidc struct {
	OidcTokens *oidc.Tokens[*oidc.IDTokenClaims]
}

func (a *ApiSessionOidc) GetAccessClaims() (*ApiAccessClaims, error) {
	claims := &ApiAccessClaims{}

	err := json.Unmarshal([]byte(a.OidcTokens.AccessToken), claims)

	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (a *ApiSessionOidc) GetId() string {
	claims, err := a.GetAccessClaims()

	if err != nil {
		return ""
	}

	return claims.ID
}

func (a *ApiSessionOidc) GetIdentityName() string {
	return a.OidcTokens.IDTokenClaims.Name
}

func (a *ApiSessionOidc) GetIdentityId() string {
	return a.OidcTokens.IDTokenClaims.Subject
}

// GetAccessHeader returns the header and header token value should be used for authentication requests
func (a *ApiSessionOidc) GetAccessHeader() (string, string) {
	if a.OidcTokens != nil {
		return "authorization", "Bearer " + a.OidcTokens.AccessToken
	}

	return "", ""
}

func (a *ApiSessionOidc) AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error {
	if a == nil {
		return errors.New("api session is nil")
	}

	header, val := a.GetAccessHeader()

	err := request.SetHeaderParam(header, val)
	if err != nil {
		return err
	}

	return nil
}

func (a *ApiSessionOidc) GetToken() []byte {
	if a.OidcTokens != nil && a.OidcTokens.AccessToken != "" {
		return []byte(a.OidcTokens.AccessToken)
	}

	return nil
}

func (a *ApiSessionOidc) GetAuthQueries() rest_model.AuthQueryList {
	//todo convert JWT auth queries to rest_model.AuthQueryList
	return nil
}

func (a *ApiSessionOidc) GetExpiresAt() *time.Time {
	if a.OidcTokens != nil {
		return &a.OidcTokens.Expiry
	}
	return nil
}

// ZitiEdgeManagement is an alias of the go-swagger generated client that allows this package to add additional
// functionality to the alias type to implement the AuthEnabledApi interface.
type ZitiEdgeManagement struct {
	*rest_management_api_client.ZitiEdgeManagement
	useOidc         bool
	versionOnce     sync.Once
	versionInfo     *rest_model.Version
	oidcExplicitSet bool
	apiUrl          *url.URL

	TotpCallback func(chan string)
}

func (self *ZitiEdgeManagement) Authenticate(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	self.versionOnce.Do(func() {
		if self.oidcExplicitSet {
			return
		}
		versionParams := manInfo.NewListVersionParams()

		versionResp, _ := self.Informational.ListVersion(versionParams)

		if versionResp != nil {
			self.versionInfo = versionResp.Payload.Data
			self.useOidc = stringz.Contains(self.versionInfo.Capabilities, string(rest_model.CapabilitiesOIDCAUTH))
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

	return &ApiSessionLegacy{Detail: resp.GetPayload().Data}, err
}

func (self *ZitiEdgeManagement) oidcAuth(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	return oidcAuth(self.apiUrl.Host, credentials, configTypes, httpClient, self.TotpCallback)
}

func (self *ZitiEdgeManagement) SetUseOidc(use bool) {
	self.oidcExplicitSet = true
	self.useOidc = use
}

func (self *ZitiEdgeManagement) RefreshApiSession(apiSession ApiSession) (ApiSession, error) {
	switch s := apiSession.(type) {
	case *ApiSessionLegacy:
		params := manCurApiSession.NewGetCurrentAPISessionParams()
		_, err := self.CurrentAPISession.GetCurrentAPISession(params, s)

		if err != nil {
			return nil, rest_util.WrapErr(err)
		}

		return s, nil
	case *ApiSessionOidc:
		tokens, err := self.ExchangeTokens(s.OidcTokens)

		if err != nil {
			return nil, err
		}

		return &ApiSessionOidc{
			OidcTokens: tokens,
		}, nil
	}

	return nil, errors.New("api session does not have any tokens")
}

func (self *ZitiEdgeManagement) ExchangeTokens(curTokens *oidc.Tokens[*oidc.IDTokenClaims]) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return exchangeTokens(self.apiUrl.String(), curTokens)
}

// ZitiEdgeClient is an alias of the go-swagger generated client that allows this package to add additional
// functionality to the alias type to implement the AuthEnabledApi interface.
type ZitiEdgeClient struct {
	*rest_client_api_client.ZitiEdgeClient
	useOidc         bool
	versionInfo     *rest_model.Version
	versionOnce     sync.Once
	oidcExplicitSet bool
	apiUrl          *url.URL

	TotpCallback func(chan string)
}

func (self *ZitiEdgeClient) Authenticate(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	self.versionOnce.Do(func() {
		if self.oidcExplicitSet {
			return
		}

		versionParams := clientInfo.NewListVersionParams()

		versionResp, _ := self.Informational.ListVersion(versionParams)

		if versionResp != nil {
			self.versionInfo = versionResp.Payload.Data
			self.useOidc = stringz.Contains(self.versionInfo.Capabilities, string(rest_model.CapabilitiesOIDCAUTH))
		}
	})

	if self.useOidc {
		return self.oidcAuth(credentials, configTypes, httpClient)
	}

	return self.legacyAuth(credentials, configTypes, httpClient)
}

func (self *ZitiEdgeClient) legacyAuth(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	params := clientAuth.NewAuthenticateParams()
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

	return &ApiSessionLegacy{Detail: resp.GetPayload().Data}, err
}

func (self *ZitiEdgeClient) oidcAuth(credentials Credentials, configTypes []string, httpClient *http.Client) (ApiSession, error) {
	return oidcAuth(self.apiUrl.Host, credentials, configTypes, httpClient, self.TotpCallback)
}

func (self *ZitiEdgeClient) SetUseOidc(use bool) {
	self.oidcExplicitSet = true
	self.useOidc = use
}

func (self *ZitiEdgeClient) RefreshApiSession(apiSession ApiSession) (ApiSession, error) {
	switch s := apiSession.(type) {
	case *ApiSessionLegacy:
		params := clientApiSession.NewGetCurrentAPISessionParams()
		_, err := self.CurrentAPISession.GetCurrentAPISession(params, s)

		if err != nil {
			return nil, rest_util.WrapErr(err)
		}

		return s, nil
	case *ApiSessionOidc:
		tokens, err := self.ExchangeTokens(s.OidcTokens)

		if err != nil {
			return nil, err
		}

		return &ApiSessionOidc{
			OidcTokens: tokens,
		}, nil
	}

	return nil, errors.New("api session does not have any tokens")
}

func (self *ZitiEdgeClient) ExchangeTokens(curTokens *oidc.Tokens[*oidc.IDTokenClaims]) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return exchangeTokens(self.apiUrl.String(), curTokens)
}

func exchangeTokens(issuer string, curTokens *oidc.Tokens[*oidc.IDTokenClaims]) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	te, err := tokenexchange.NewTokenExchanger(issuer)

	if err != nil {
		return nil, err
	}

	accessResp, err := tokenexchange.ExchangeToken(te, curTokens.RefreshToken, oidc.RefreshTokenType, "", "", nil, nil, nil, oidc.AccessTokenType)

	if err != nil {
		return nil, err
	}

	//TODO: be smarter, only refresh refresh token if the new access token lives beyond refresh
	refreshResp, err := tokenexchange.ExchangeToken(te, curTokens.RefreshToken, oidc.RefreshTokenType, "", "", nil, nil, nil, oidc.RefreshTokenType)

	if err != nil {
		return nil, err
	}

	idResp, err := tokenexchange.ExchangeToken(te, curTokens.RefreshToken, oidc.RefreshTokenType, "", "", nil, nil, nil, oidc.IDTokenType)

	if err != nil {
		return nil, err
	}

	idClaims := &oidc.IDTokenClaims{}

	err = json.Unmarshal([]byte(idResp.AccessToken), idClaims)

	if err != nil {
		return nil, err
	}

	return &oidc.Tokens[*oidc.IDTokenClaims]{
		Token: &oauth2.Token{
			AccessToken:  accessResp.AccessToken,
			TokenType:    accessResp.TokenType,
			RefreshToken: refreshResp.RefreshToken,
			Expiry:       time.Time{},
		},
		IDTokenClaims: idClaims,
		IDToken:       idResp.AccessToken, //access token is used to hold id token per zitadel comments
	}, nil
}

type authPayload struct {
	*rest_model.Authenticate
	AuthRequestId string `json:"id"`
}

type totpCodePayload struct {
	rest_model.MfaCode
	AuthRequestId string `json:"id"`
}

func (a *authPayload) toMap() map[string]string {
	configTypes := strings.Join(a.ConfigTypes, ",")
	result := map[string]string{
		"id":            a.AuthRequestId,
		"configTypes":   configTypes,
		"password":      string(a.Password),
		"username":      string(a.Username),
		"envArch":       a.EnvInfo.Arch,
		"envOs":         a.EnvInfo.Os,
		"envOsRelease":  a.EnvInfo.OsRelease,
		"envOsVersion":  a.EnvInfo.OsVersion,
		"sdkAppID":      a.SdkInfo.AppID,
		"sdkAppVersion": a.SdkInfo.AppVersion,
		"sdkBranch":     a.SdkInfo.Branch,
		"sdkRevision":   a.SdkInfo.Revision,
		"sdkType":       a.SdkInfo.Type,
		"sdkVersion":    a.SdkInfo.Version,
	}

	return result
}

func oidcAuth(issuer string, credentials Credentials, configTypes []string, httpClient *http.Client, totpCallback func(chan string)) (ApiSession, error) {
	payload := &authPayload{
		Authenticate: credentials.Payload(),
	}
	method := credentials.Method()
	payload.ConfigTypes = configTypes

	certs := credentials.TlsCerts()
	if len(certs) != 0 {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.Certificates = certs
			transport.CloseIdleConnections()
		}
	}

	rpServer, err := newLocalRpServer(issuer, method)

	if err != nil {
		return nil, err
	}

	rpServer.Start()
	defer rpServer.Stop()

	client := resty.NewWithClient(httpClient)
	client.SetRedirectPolicy(resty.DomainCheckRedirectPolicy("127.0.0.1", "localhost"))
	resp, err := client.R().Get(rpServer.LoginUri)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("local rp login response is expected to be HTTP status %d got %d with body: %s", http.StatusOK, resp.StatusCode(), resp.Body())
	}
	payload.AuthRequestId = resp.Header().Get(AuthRequestIdHeader)

	if payload.AuthRequestId == "" {
		return nil, errors.New("could not find auth request id header")
	}

	opLoginUri := "https://" + resp.RawResponse.Request.URL.Host + "/oidc/login/" + method
	totpUri := "https://" + resp.RawResponse.Request.URL.Host + "/oidc/login/totp"

	formData := payload.toMap()

	req := client.R()
	clientRequest := asClientRequest(req, client)

	err = credentials.AuthenticateRequest(clientRequest, strfmt.Default)

	if err != nil {
		return nil, err
	}

	resp, err = req.SetFormData(formData).Post(opLoginUri)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("remote op login response is expected to be HTTP status %d got %d with body: %s", http.StatusOK, resp.StatusCode(), resp.Body())
	}

	authRequestId := resp.Header().Get(AuthRequestIdHeader)
	totpRequiredHeader := resp.Header().Get(TotpRequiredHeader)
	totpRequired := totpRequiredHeader != ""
	totpCode := ""

	if totpRequired {

		if totpCallback == nil {
			return nil, errors.New("totp is required but not totp callback was defined")
		}
		codeChan := make(chan string)
		go totpCallback(codeChan)

		select {
		case code := <-codeChan:
			totpCode = code
		case <-time.After(30 * time.Minute):
			return nil, fmt.Errorf("timedout waiting for totpT callback")
		}

		resp, err = client.R().SetBody(&totpCodePayload{
			MfaCode: rest_model.MfaCode{
				Code: &totpCode,
			},
			AuthRequestId: authRequestId,
		}).Post(totpUri)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode() != http.StatusOK {
			apiErr := &errorz.ApiError{}
			err = json.Unmarshal(resp.Body(), apiErr)

			if err != nil {
				return nil, fmt.Errorf("could not verify TOTP MFA code recieved %d - could not parse body: %s", resp.StatusCode(), string(resp.Body()))
			}

			return nil, apiErr

		}
	}

	var outTokens *oidc.Tokens[*oidc.IDTokenClaims]

	tokens := <-rpServer.TokenChan

	if tokens == nil {
		return nil, errors.New("authentication did not complete, received nil tokens")
	}
	outTokens = tokens

	return &ApiSessionOidc{
		OidcTokens: outTokens,
	}, nil
}

// restyClientRequest is meant to mimic open api's client request which is a combination
// of resty's request and client.
type restyClientRequest struct {
	restyRequest *resty.Request
	restyClient  *resty.Client
}

func (r *restyClientRequest) SetHeaderParam(s string, s2 ...string) error {
	r.restyRequest.Header[s] = s2
	return nil
}

func (r *restyClientRequest) GetHeaderParams() http.Header {
	return r.restyRequest.Header
}

func (r *restyClientRequest) SetQueryParam(s string, s2 ...string) error {
	r.restyRequest.QueryParam[s] = s2
	return nil
}

func (r *restyClientRequest) SetFormParam(s string, s2 ...string) error {
	r.restyRequest.FormData[s] = s2
	return nil
}

func (r *restyClientRequest) SetPathParam(s string, s2 string) error {
	r.restyRequest.PathParams[s] = s2
	return nil
}

func (r *restyClientRequest) GetQueryParams() url.Values {
	return r.restyRequest.QueryParam
}

func (r *restyClientRequest) SetFileParam(s string, closer ...runtime.NamedReadCloser) error {
	for _, curCloser := range closer {
		r.restyRequest.SetFileReader(s, curCloser.Name(), curCloser)
	}

	return nil
}

func (r *restyClientRequest) SetBodyParam(i interface{}) error {
	r.restyRequest.SetBody(i)
	return nil
}

func (r *restyClientRequest) SetTimeout(duration time.Duration) error {
	r.restyClient.SetTimeout(duration)
	return nil
}

func (r *restyClientRequest) GetMethod() string {
	return r.restyRequest.Method
}

func (r *restyClientRequest) GetPath() string {
	return r.restyRequest.URL
}

func (r *restyClientRequest) GetBody() []byte {
	return r.restyRequest.Body.([]byte)
}

func (r *restyClientRequest) GetBodyParam() interface{} {
	return r.restyRequest.Body
}

func (r *restyClientRequest) GetFileParam() map[string][]runtime.NamedReadCloser {
	return nil
}

func asClientRequest(request *resty.Request, client *resty.Client) runtime.ClientRequest {
	return &restyClientRequest{request, client}
}
