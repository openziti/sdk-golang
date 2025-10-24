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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/errorz"
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
	ApiUrls      []*url.URL
	CaPool       *x509.CertPool
	TotpCallback func(chan string)
	Proxy        func(r *http.Request) (*url.URL, error)
}

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

func oidcAuth(clientTransportPool ClientTransportPool, credentials Credentials, configTypeOverrides []string, httpClient *http.Client, totpCallback func(chan string)) (ApiSession, error) {
	payload := &authPayload{
		Authenticate: credentials.Payload(),
	}
	method := credentials.Method()

	if method == AuthMethodEmpty {
		return nil, fmt.Errorf("auth method %s cannot be used for authentication, please provide alternate credentials", AuthMethodEmpty)
	}

	if configTypeOverrides != nil {
		payload.ConfigTypes = configTypeOverrides
	}

	certs := credentials.TlsCerts()

	if len(certs) != 0 {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.Certificates = certs
			transport.CloseIdleConnections()
		}
	}

	var outTokens *oidc.Tokens[*oidc.IDTokenClaims]

	_, err := clientTransportPool.TryTransportForF(func(transport *ApiClientTransport) (any, error) {
		rpServer, err := newLocalRpServer(transport.ApiUrl.Host, method)

		if err != nil {
			return nil, err
		}

		rpServer.Start()
		defer rpServer.Stop()

		client := resty.NewWithClient(httpClient)
		apiHost := transport.ApiUrl.Hostname()

		client.SetRedirectPolicy(resty.DomainCheckRedirectPolicy("127.0.0.1", "localhost", apiHost))
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

		opLoginUri := "https://" + resp.RawResponse.Request.URL.Host + "/oidc/login/" + string(method)
		totpUri := "https://" + resp.RawResponse.Request.URL.Host + "/oidc/login/totp"

		formData := payload.toValues()

		req := client.R()
		clientRequest := asClientRequest(req, client)

		err = credentials.AuthenticateRequest(clientRequest, strfmt.Default)

		if err != nil {
			return nil, err
		}

		resp, err = req.SetFormDataFromValues(formData).Post(opLoginUri)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode() != http.StatusOK {
			return nil, fmt.Errorf("remote op login response is expected to be HTTP status %d got %d with body: %s", http.StatusOK, resp.StatusCode(), resp.Body())
		}

		authRequestId := payload.AuthRequestId
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

		var tokens *oidc.Tokens[*oidc.IDTokenClaims]
		select {
		case tokens = <-rpServer.TokenChan:
		case <-time.After(30 * time.Minute):
		}

		if tokens == nil {
			return nil, errors.New("authentication did not complete, received nil tokens")
		}
		outTokens = tokens

		return nil, nil
	})

	if err != nil {
		return nil, err
	}

	return &ApiSessionOidc{
		OidcTokens:     outTokens,
		RequestHeaders: credentials.GetRequestHeaders(),
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
