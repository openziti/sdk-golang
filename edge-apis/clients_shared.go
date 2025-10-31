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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// ApiType is an interface constraint for generics. The underlying go-swagger types only have fields, which are
// insufficient to attempt to make a generic type from. Instead, this constraint is used that points at the
// aliased types.
type ApiType interface {
	ZitiEdgeManagement | ZitiEdgeClient
}

type OidcEnabledApi interface {
	// SetUseOidc forces an API Client to operate in OIDC mode (true) or legacy mode (false). The state of the controller
	// is ignored and dynamic enable/disable of OIDC support is suspended.
	SetUseOidc(use bool)

	// SetAllowOidcDynamicallyEnabled sets whether clients will check the controller for OIDC support or not. If supported
	// OIDC is favored over legacy authentication.
	SetAllowOidcDynamicallyEnabled(allow bool)
}

// ApiClientConfig contains configuration options for creating API clients.
type ApiClientConfig struct {
	ApiUrls          []*url.URL
	CaPool           *x509.CertPool
	TotpCodeProvider TotpCodeProvider
	Components       *Components
	Proxy            func(r *http.Request) (*url.URL, error)
}

// exchangeTokens exchanges OIDC tokens for refreshed tokens. It uses refresh tokens preferentially,
// falling back to non-expired access tokens if refresh is unavailable.
func exchangeTokens(clientTransportPool ClientTransportPool, curTokens *oidc.Tokens[*oidc.IDTokenClaims], client *http.Client) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	subjectToken := ""
	var subjectTokenType oidc.TokenType

	if curTokens.RefreshToken != "" {
		subjectToken = curTokens.RefreshToken
		subjectTokenType = oidc.RefreshTokenType
	} else if curTokens.AccessToken != "" {
		// if subjectToken is "", then we don't have a refresh token, attempt to exchange a non-expired access token
		expired, err := isAccessTokenExpired(curTokens)

		if err != nil {
			return nil, err
		}

		if expired {
			return nil, errors.New("cannot exchange token: refresh token not found, access token expired")
		}

		if curTokens.AccessToken == "" {
			return nil, errors.New("cannot exchange token: refresh token not found, access token not found")
		}
		subjectToken = curTokens.AccessToken
		subjectTokenType = oidc.AccessTokenType
	}

	if subjectToken == "" {
		return nil, errors.New("cannot exchange token: refresh token not found, access token not found or expired")
	}

	var outTokens *oidc.Tokens[*oidc.IDTokenClaims]

	_, err := clientTransportPool.TryTransportForF(func(transport *ApiClientTransport) (any, error) {
		timeoutCtx, cancelF := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelF()

		apiHost := transport.ApiUrl.Host
		issuer := "https://" + apiHost + "/oidc"
		tokenEndpoint := "https://" + apiHost + "/oidc/oauth/token"

		te, err := tokenexchange.NewTokenExchangerClientCredentials(timeoutCtx, issuer, "native", "", tokenexchange.WithHTTPClient(client), tokenexchange.WithStaticTokenEndpoint(issuer, tokenEndpoint))

		if err != nil {
			return nil, err
		}

		var tokenResponse *oidc.TokenExchangeResponse

		now := time.Now()

		switch subjectTokenType {
		case oidc.RefreshTokenType:
			tokenResponse, err = tokenexchange.ExchangeToken(timeoutCtx, te, subjectToken, subjectTokenType, "", "", nil, nil, nil, oidc.RefreshTokenType)
		case oidc.AccessTokenType:
			tokenResponse, err = tokenexchange.ExchangeToken(timeoutCtx, te, subjectToken, subjectTokenType, "", "", nil, nil, nil, oidc.AccessTokenType)
		}

		if err != nil {
			return nil, err
		}

		idResp, err := tokenexchange.ExchangeToken(timeoutCtx, te, subjectToken, subjectTokenType, "", "", nil, nil, nil, oidc.IDTokenType)

		if err != nil {
			return nil, err
		}

		idClaims := &IdClaims{}

		//access token is used to hold id token per zitadel comments
		_, _, err = jwt.NewParser().ParseUnverified(idResp.AccessToken, idClaims)

		if err != nil {
			return nil, err
		}

		outTokens = &oidc.Tokens[*oidc.IDTokenClaims]{
			Token: &oauth2.Token{
				AccessToken:  tokenResponse.AccessToken,
				TokenType:    tokenResponse.TokenType,
				RefreshToken: tokenResponse.RefreshToken,
				Expiry:       now.Add(time.Second * time.Duration(tokenResponse.ExpiresIn)),
			},
			IDTokenClaims: &idClaims.IDTokenClaims,
			IDToken:       idResp.AccessToken, //access token field is used to hold id token per zitadel comments
		}

		return outTokens, nil
	})

	if err != nil {
		return nil, err
	}

	return outTokens, nil
}

// isAccessTokenExpired checks if an access token is expired. If token metadata is unavailable,
// it parses the JWT claims to determine expiration.
func isAccessTokenExpired(tokens *oidc.Tokens[*oidc.IDTokenClaims]) (bool, error) {
	if tokens.Expiry.IsZero() {
		//meta data isn't set, we need to parse the token
		idClaims := &IdClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(tokens.AccessToken, idClaims)

		if err != nil {
			return true, fmt.Errorf("token meta data is empty, could not parse token to determine token validity: %w", err)
		}

		//failed to parse out a required exp field for oAuth2, we have no idea of this token is good
		if idClaims.GetExpiration().IsZero() {
			return true, errors.New("token meta data is empty, parsed token does not have an expiration value")
		}

		return idClaims.GetExpiration().Before(time.Now()), nil
	}

	return tokens.Expiry.Before(time.Now()), nil
}

type authPayload struct {
	*rest_model.Authenticate
	AuthRequestId string `json:"id"`
}

type totpCodePayload struct {
	rest_model.MfaCode
	AuthRequestId string `json:"id"`
}

func (a *authPayload) toValues() url.Values {
	result := url.Values{
		"id":            []string{a.AuthRequestId},
		"password":      []string{string(a.Password)},
		"username":      []string{string(a.Username)},
		"configTypes":   a.ConfigTypes,
		"envArch":       []string{a.EnvInfo.Arch},
		"envOs":         []string{a.EnvInfo.Os},
		"envOsRelease":  []string{a.EnvInfo.OsRelease},
		"envOsVersion":  []string{a.EnvInfo.OsVersion},
		"sdkAppID":      []string{a.SdkInfo.AppID},
		"sdkAppVersion": []string{a.SdkInfo.AppVersion},
		"sdkBranch":     []string{a.SdkInfo.Branch},
		"sdkRevision":   []string{a.SdkInfo.Revision},
		"sdkType":       []string{a.SdkInfo.Type},
		"sdkVersion":    []string{a.SdkInfo.Version},
	}

	return result
}

// oidcAuth performs OIDC authentication using OAuth flow with PKCE.
// It handles TOTP if required and returns an OIDC session with tokens.
func oidcAuth(clientTransportPool ClientTransportPool, credentials Credentials, configTypeOverrides []string, httpClient *http.Client, totpCodeProvider TotpCodeProvider) (ApiSession, error) {
	if credentials.Method() == AuthMethodEmpty {
		return nil, fmt.Errorf("auth method %s cannot be used for authentication, please provide alternate credentials", AuthMethodEmpty)
	}

	certificates := credentials.TlsCerts()

	if len(certificates) != 0 {
		if transport, ok := httpClient.Transport.(TlsAwareTransport); ok {
			tlsClientConf := transport.GetTlsClientConfig()
			tlsClientConf.Certificates = certificates
			transport.CloseIdleConnections()
		}
	}

	var outTokens *oidc.Tokens[*oidc.IDTokenClaims]

	_, err := clientTransportPool.TryTransportForF(func(transport *ApiClientTransport) (any, error) {

		edgeOidcAuth := newEdgeOidcAuthenticator(transport, httpClient)

		var err error
		outTokens, err = edgeOidcAuth.Authenticate(credentials, totpCodeProvider, configTypeOverrides)

		if err != nil {
			return nil, err
		}

		return outTokens, nil
	})

	if err != nil {
		return nil, err
	}

	return &ApiSessionOidc{
		OidcTokens:     outTokens,
		RequestHeaders: credentials.GetRequestHeaders(),
	}, nil
}

// edgeOidcAuthenticator handles the OAuth 2.0 PKCE authentication flow for the Ziti Edge API.
// It submits user credentials to the authorization endpoint, handles optional TOTP verification,
// and exchanges the authorization code for OIDC tokens. The HTTP client follows redirects
// during the authorization flow and extracts the authorization code from the final redirect.
type edgeOidcAuthenticator struct {
	httpClient          *http.Client
	configTypeOverrides []string
	client              *resty.Client
	apiHost             string
	redirectUri         string
}

// newEdgeOidcAuthenticator creates a new edgeOidcAuthenticator configured for PKCE authentication.
// It sets up an HTTP client with a custom redirect policy that follows redirects during the
// authorization flow but stops when the callback redirect URI is reached, allowing code extraction
// from the redirect URL. The redirectUri parameter defines where the authorization server will
// redirect with the authorization code in the query parameters.
func newEdgeOidcAuthenticator(transport *ApiClientTransport, httpClient *http.Client) *edgeOidcAuthenticator {
	const DefaultOidcRedirectUri = "http://localhost/auth/callback"

	client := resty.NewWithClient(httpClient)

	// allows resty to follow redirects for us during the OAuth flow, but not for the end PKCE callback
	// there is no server running for that redirect to hit, as it is this code
	client.SetRedirectPolicy(RedirectUntilUrlPrefix(DefaultOidcRedirectUri))

	apiHost := transport.ApiUrl.Host

	return &edgeOidcAuthenticator{
		httpClient:  httpClient,
		client:      client,
		apiHost:     apiHost,
		redirectUri: DefaultOidcRedirectUri,
	}
}

// Authenticate performs the complete OAuth 2.0 PKCE authentication flow. It initiates authorization
// with PKCE parameters, submits credentials and handles optional TOTP verification, then exchanges
// the resulting authorization code for OIDC tokens.
func (e *edgeOidcAuthenticator) Authenticate(credentials Credentials, totpCodeProvider TotpCodeProvider, configTypeOverrides []string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	pkceParams, err := newPkceParameters()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE parameters: %w", err)
	}

	verificationParams, err := e.initOAuthFlow(pkceParams)

	if err != nil {
		return nil, fmt.Errorf("failed to initiate authorization flow: %w", err)
	}

	redirectResp, err := e.handlePrimaryAndSecondaryAuth(verificationParams, credentials, totpCodeProvider, configTypeOverrides)
	if err != nil {
		return nil, err
	}

	tokens, err := e.finishOAuthFlow(redirectResp, verificationParams, pkceParams)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// finishOAuthFlow extracts the authorization code from the callback redirect and exchanges it for tokens.
// The authorization server returns the code as a query parameter in the Location header of the redirect response.
// The code is then used with the PKCE verifier to obtain OIDC tokens via the token endpoint.
func (e *edgeOidcAuthenticator) finishOAuthFlow(redirectResp *resty.Response, verificationParams *verificationParameters, pkceParams *pkceParameters) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	if redirectResp.StatusCode() != http.StatusFound {
		return nil, fmt.Errorf("authentication failed, expected a 302, got %d", redirectResp.StatusCode())
	}

	redirectStr := redirectResp.Header().Get("Location")
	redirectUrl, err := url.Parse(redirectStr)
	if err != nil {
		return nil, fmt.Errorf("authentication failed, could not parse redirect url [%s]: %w", redirectStr, err)
	}

	state := redirectUrl.Query().Get("state")

	if state == "" {
		return nil, errors.New("authentication failed, no state found in redirect url")
	}

	if state != verificationParams.State {
		return nil, errors.New("authentication failed, state mismatch")
	}

	code := redirectUrl.Query().Get("code")
	if code == "" {
		return nil, errors.New("authentication failed, no code found in redirect url")
	}

	tokens, err := e.exchangeAuthorizationCodeForTokens(code, pkceParams)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	if tokens.IDTokenClaims.Nonce != verificationParams.Nonce {
		return nil, errors.New("authentication failed, nonce mismatch")
	}

	return tokens, nil
}

// handlePrimaryAndSecondaryAuth submits credentials to the authorization endpoint and handles optional TOTP.
func (e *edgeOidcAuthenticator) handlePrimaryAndSecondaryAuth(verificationParams *verificationParameters, credentials Credentials, totpCodeProvider TotpCodeProvider, configTypeOverrides []string) (*resty.Response, error) {
	loginUri := "https://" + e.apiHost + "/oidc/login/" + string(credentials.Method())
	totpUri := "https://" + e.apiHost + "/oidc/login/totp"

	payload := &authPayload{
		Authenticate:  credentials.Payload(),
		AuthRequestId: verificationParams.AuthRequestId,
	}

	if e.configTypeOverrides != nil {
		payload.ConfigTypes = e.configTypeOverrides
	}

	formData := payload.toValues()
	req := e.client.R()
	clientRequest := asClientRequest(req, e.client)

	err := credentials.AuthenticateRequest(clientRequest, strfmt.Default)
	if err != nil {
		return nil, err
	}

	resp, err := req.SetFormDataFromValues(formData).Post(loginUri)
	if err != nil {
		return nil, err
	}

	// no additional secondary authentication required
	if resp.StatusCode() == http.StatusFound {
		return resp, nil
	}

	// something went wrong
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("credential submission failed with status %d", resp.StatusCode())
	}

	totpRequiredHeader := resp.Header().Get(TotpRequiredHeader)
	if totpRequiredHeader == "" {
		return nil, errors.New("response was not a redirect and TOTP is not required, unknown additional authentication steps are required but unsupported")
	}

	if totpCodeProvider == nil {
		return nil, errors.New("totp is required but no totp callback was defined")
	}

	totpCodeResultCh := totpCodeProvider.GetTotpCode()
	var totpCode string

	select {
	case totpCodeResult := <-totpCodeResultCh:
		if totpCodeResult.Err != nil {
			return nil, fmt.Errorf("error getting totp code: %w", totpCodeResult.Err)
		}
		totpCode = totpCodeResult.Code
	case <-time.After(30 * time.Minute):
		return nil, fmt.Errorf("timeout waiting for totp code provider")
	}

	resp, err = e.client.R().SetBody(&totpCodePayload{
		MfaCode: rest_model.MfaCode{
			Code: &totpCode,
		},
		AuthRequestId: payload.AuthRequestId,
	}).Post(totpUri)

	if err != nil {
		return nil, err
	}

	switch resp.StatusCode() {
	case http.StatusOK:
		return nil, errors.New("totp code verified, but additional authentication is required that is not supported or not configured, cannot authenticate")
	case http.StatusFound:
		return resp, nil
	case http.StatusBadRequest:
		return nil, errors.New("totp code did not verify")
	default:
		return nil, fmt.Errorf("unexpected response code %d from TOTP verification", resp.StatusCode())
	}
}

// initOAuthFlow initiates the OAuth authorization request with PKCE parameters and returns the authorization request ID.
func (e *edgeOidcAuthenticator) initOAuthFlow(pkceParams *pkceParameters) (*verificationParameters, error) {
	verificationParams := &verificationParameters{
		State: generateRandomState(),
		Nonce: generateNonce(),
	}

	authUrl := "https://" + e.apiHost + "/oidc/authorize?" + url.Values{
		"client_id":             []string{"native"},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid offline_access"},
		"state":                 []string{verificationParams.State},
		"code_challenge":        []string{pkceParams.Challenge},
		"code_challenge_method": []string{pkceParams.Method},
		"redirect_uri":          []string{e.redirectUri},
		"nonce":                 []string{verificationParams.Nonce},
	}.Encode()

	resp, err := e.client.R().SetDoNotParseResponse(true).Get(authUrl)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.RawResponse.Body.Close() }()

	verificationParams.AuthRequestId = resp.Header().Get(AuthRequestIdHeader)
	if verificationParams.AuthRequestId == "" {
		return nil, errors.New("could not find auth request id header from authorize endpoint")
	}

	return verificationParams, nil
}

// RedirectUntilUrlPrefix returns a redirect policy that follows redirects until the request URL
// matches one of the provided URL prefixes. Once a matching prefix is encountered, the redirect
// is not followed, allowing the caller to inspect the redirect response.
func RedirectUntilUrlPrefix(urlPrefixToStopAt ...string) resty.RedirectPolicy {
	return resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		reqUrl := req.URL.String()
		for _, urlToStopAt := range urlPrefixToStopAt {
			if strings.HasPrefix(reqUrl, urlToStopAt) {
				return http.ErrUseLastResponse
			}
		}
		return nil
	})
}

// exchangeAuthorizationCodeForTokens exchanges an authorization code and PKCE verifier for OIDC tokens.
func (e *edgeOidcAuthenticator) exchangeAuthorizationCodeForTokens(code string, pkceParams *pkceParameters) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	tokenEndpoint := "https://" + e.apiHost + "/oidc/oauth/token"

	tokenResp, err := e.client.R().SetFormData(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "native",
		"code_verifier": pkceParams.Verifier,
		"code":          code,
		"redirect_uri":  "http://localhost/auth/callback",
	}).Post(tokenEndpoint)

	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code for tokens: %w", err)
	}

	if tokenResp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", tokenResp.StatusCode(), string(tokenResp.Body()))
	}

	// Parse token response
	var tokenData map[string]interface{}
	err = json.Unmarshal(tokenResp.Body(), &tokenData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	accessToken, ok := tokenData["access_token"].(string)
	if !ok {
		return nil, errors.New("access_token not found in token response")
	}

	refreshToken, _ := tokenData["refresh_token"].(string)
	expiresIn, _ := tokenData["expires_in"].(float64)

	// Parse ID token
	idToken, _ := tokenData["id_token"].(string)
	idClaims := &IdClaims{}

	if idToken != "" {
		_, _, err = jwt.NewParser().ParseUnverified(idToken, idClaims)
		if err != nil {
			// Log but don't fail if ID token parsing fails
			return nil, fmt.Errorf("failed to parse ID token: %w", err)
		}
	}

	tokens := &oidc.Tokens[*oidc.IDTokenClaims]{
		Token: &oauth2.Token{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			RefreshToken: refreshToken,
			Expiry:       time.Now().Add(time.Duration(expiresIn) * time.Second),
		},
		IDTokenClaims: &idClaims.IDTokenClaims,
		IDToken:       idToken,
	}

	return tokens, nil
}

// pkceParameters holds the PKCE parameters used for OAuth 2.0 Proof Key for Public Clients flow.
type pkceParameters struct {
	Verifier  string
	Challenge string
	Method    string
}

type verificationParameters struct {
	State         string
	AuthRequestId string
	Nonce         string
}

// newPkceParameters generates PKCE parameters for OAuth 2.0 PKCE flow.
// It creates a random code verifier and derives the code challenge by applying SHA256 hashing.
func newPkceParameters() (*pkceParameters, error) {
	var err error
	params := &pkceParameters{
		Method: "S256",
	}

	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	params.Verifier = base64URLEncodeNoPadding(b)

	hash := sha256.Sum256([]byte(params.Verifier))
	params.Challenge = base64URLEncodeNoPadding(hash[:])

	return params, nil
}

// generateRandomState generates a random state string for CSRF protection.
func generateRandomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64URLEncodeNoPadding(b)
}

// generateNonce generates a random nonce for binding the authorization request to the ID token.
func generateNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// base64URLEncodeNoPadding encodes data to base64URL format without padding.
// Padding is removed because base64URL is designed to work in URLs and query strings where
// the '=' character may have special meaning.
func base64URLEncodeNoPadding(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
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
