package ziti

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge-api/rest_client_api_client"
	"github.com/openziti/edge-api/rest_client_api_client/authentication"
	"github.com/openziti/edge-api/rest_client_api_client/current_api_session"
	"github.com/openziti/edge-api/rest_client_api_client/current_identity"
	"github.com/openziti/edge-api/rest_client_api_client/posture_checks"
	"github.com/openziti/edge-api/rest_client_api_client/service"
	"github.com/openziti/edge-api/rest_client_api_client/session"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
	nfPem "github.com/openziti/foundation/v2/pem"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	"net/url"
	"time"
)

// CtrlClient is a stateful version of ZitiEdgeClient that simplifies operations
type CtrlClient struct {
	*rest_client_api_client.ZitiEdgeClient
	Authenticator rest_util.Authenticator

	ApiSession *rest_model.CurrentAPISessionDetail

	lastServiceUpdate  *strfmt.DateTime
	lastServiceRefresh *strfmt.DateTime

	EdgeClientApiUrl *url.URL

	ApiSessionIdentity          identity.Identity
	ApiSessionCertificateDetail rest_model.CurrentAPISessionCertificateDetail
	ApiSessionCsr               x509.CertificateRequest
	ApiSessionCertificate       *x509.Certificate
	ApiSessionPrivateKey        *ecdsa.PrivateKey
	CaPool                      *x509.CertPool
	ApiSessionCertInstance      string

	PostureCache *posture.Cache
}

// AuthenticateRequest allows a CtrlClient to act as a ClientAuthInfoWriter, authenticating go-swagger generated client requests.
func (client *CtrlClient) AuthenticateRequest(request runtime.ClientRequest, registry strfmt.Registry) error {
	if client.ApiSession != nil {
		return request.SetHeaderParam("zt-session", *client.ApiSession.Token)
	}

	return nil
}

// GetCurrentApiSession returns the current cached ApiSession or nil
func (client *CtrlClient) GetCurrentApiSession() *rest_model.CurrentAPISessionDetail {
	return client.ApiSession
}

// Refresh will contact the controller extending the current ApiSession
func (client *CtrlClient) Refresh() (*time.Time, error) {
	resp, err := client.CurrentAPISession.GetCurrentAPISession(&current_api_session.GetCurrentAPISessionParams{}, nil)

	if err != nil {
		return nil, err
	}
	expiresAt := time.Time(*resp.Payload.Data.ExpiresAt)
	return &expiresAt, nil
}

// IsServiceListUpdateAvailable will contact the controller to determine if a new set of services are available. Service
// updates could entail gaining/losing services access via policy or runtime authorization revocation due to posture
// checks.
func (client *CtrlClient) IsServiceListUpdateAvailable() (bool, error) {
	if client.lastServiceUpdate == nil {
		return true, nil
	}

	resp, err := client.CurrentAPISession.ListServiceUpdates(&current_api_session.ListServiceUpdatesParams{}, nil)

	if err != nil {
		return false, err
	}

	return resp.Payload.Data.LastChangeAt.Equal(*client.lastServiceUpdate), nil
}

// SetInfo is used to set the environment and SDK information that is submitted during authentication requests.
// Environment information includes OS level information while SDK information includes application and build
// information.
func (client *CtrlClient) SetInfo(envInfo *rest_model.EnvInfo, sdkInfo *rest_model.SdkInfo) {
	client.Authenticator.SetInfo(envInfo, sdkInfo)
}

// Authenticate attempts to use authenticate, overwriting any existing ApiSession.
func (client *CtrlClient) Authenticate() (*rest_model.CurrentAPISessionDetail, error) {
	var err error

	client.ApiSessionCertificate = nil
	client.ApiSession, err = client.Authenticator.Authenticate(client.EdgeClientApiUrl)

	if client.ApiSession != nil {
		_, err := client.GetIdentity()
		if err != nil {
			return nil, err
		}
	}

	return client.ApiSession, err
}

// AuthenticateMFA handles MFA authentication queries may be provided. AuthenticateMFA allows
// the current identity for their current api session to attempt to pass MFA authentication.
func (client *CtrlClient) AuthenticateMFA(code string) error {
	_, err := client.ZitiEdgeClient.Authentication.AuthenticateMfa(&authentication.AuthenticateMfaParams{
		MfaAuth: &rest_model.MfaCode{
			Code: &code,
		},
	}, nil, nil)

	if err != nil {
		return err
	}

	return nil
}

// SendPostureResponse creates a posture response (some state data the controller has requested) for services. This
// information is used to determine runtime authorization access to services via posture checks.
func (client *CtrlClient) SendPostureResponse(response rest_model.PostureResponseCreate) error {
	params := posture_checks.NewCreatePostureResponseParams()
	params.PostureResponse = response
	_, err := client.PostureChecks.CreatePostureResponse(params, nil)

	if err != nil {
		return err
	}
	return nil
}

// SendPostureResponseBulk provides the same functionality as SendPostureResponse but allows multiple responses
// to be sent in a single request.
func (client *CtrlClient) SendPostureResponseBulk(responses []rest_model.PostureResponseCreate) error {
	params := posture_checks.NewCreatePostureResponseBulkParams()
	params.PostureResponse = responses
	_, err := client.PostureChecks.CreatePostureResponseBulk(params, nil)

	if err != nil {
		return err
	}
	return nil
}

// GetCurrentIdentity returns the rest_model.IdentityDetail for the currently authenticated ApiSession.
func (client *CtrlClient) GetCurrentIdentity() (*rest_model.IdentityDetail, error) {
	params := current_identity.NewGetCurrentIdentityParams()
	resp, err := client.CurrentIdentity.GetCurrentIdentity(params, nil)

	if err != nil {
		return nil, err
	}

	return resp.Payload.Data, nil
}

// GetSession returns the full rest_model.SessionDetail for a specific id
func (client *CtrlClient) GetSession(id string) (*rest_model.SessionDetail, error) {
	params := session.NewDetailSessionParams()
	params.ID = id
	resp, err := client.Session.DetailSession(params, nil)

	if err != nil {
		return nil, err
	}

	return resp.Payload.Data, nil
}

// GetIdentity returns the identity.Identity used to facilitate authentication. Each identity.Identity instance
// may provide authentication material in the form of x509 certificates and private keys and/or trusted CA pools.
func (client *CtrlClient) GetIdentity() (identity.Identity, error) {
	if client.ApiSessionIdentity != nil {
		return client.ApiSessionIdentity, nil
	}

	if certProvider, ok := client.Authenticator.(rest_util.CertProvider); ok {
		clientConfig := certProvider.ClientTLSConfig()
		return identity.NewClientTokenIdentityWithPool([]*x509.Certificate{clientConfig.Certificates[0].Leaf}, clientConfig.Certificates[0].PrivateKey, certProvider.CA()), nil
	}

	if client.ApiSessionCertificate == nil {
		err := client.EnsureApiSessionCertificate()

		if err != nil {
			return nil, fmt.Errorf("could not ensure an API Session certificate is available: %v", err)
		}
	}

	return identity.NewClientTokenIdentityWithPool([]*x509.Certificate{client.ApiSessionCertificate}, client.ApiSessionPrivateKey, client.CaPool), nil
}

// EnsureApiSessionCertificate will create an ApiSessionCertificate if one does not already exist.
func (client *CtrlClient) EnsureApiSessionCertificate() error {
	if client.ApiSessionCertificate == nil {
		return client.NewApiSessionCertificate()
	}

	return nil
}

// NewApiSessionCertificate will create a new ephemeral private key used to generate an ephemeral certificate
// that may be used with the current ApiSession. The generated certificate and private key are scoped to the
// ApiSession used to create it.
func (client *CtrlClient) NewApiSessionCertificate() error {
	if client.ApiSessionCertInstance == "" {
		client.ApiSessionCertInstance = uuid.NewString()
	}

	if client.ApiSessionPrivateKey == nil {
		var err error
		client.ApiSessionPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		if err != nil {
			return fmt.Errorf("could not generate private key for api session certificate: %v", err)
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Ziti SDK"},
			OrganizationalUnit: []string{"golang"},
			CommonName:         "golang-sdk-" + client.ApiSessionCertInstance + "-" + uuid.NewString(),
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, client.ApiSessionPrivateKey)
	if err != nil {
		panic(err)
	}
	block := &pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: nil,
		Bytes:   csrBytes,
	}
	csrPemString := string(pem.EncodeToMemory(block))

	params := current_api_session.NewCreateCurrentAPISessionCertificateParams()
	params.SessionCertificate = &rest_model.CurrentAPISessionCertificateCreate{
		Csr: &csrPemString,
	}

	resp, err := client.ZitiEdgeClient.CurrentAPISession.CreateCurrentAPISessionCertificate(params, nil)

	if err != nil {
		return err
	}

	certs := nfPem.PemBytesToCertificates([]byte(*resp.Payload.Data.Certificate))

	if len(certs) == 0 {
		return fmt.Errorf("expected at least 1 certificate creating an API Session Certificate, got 0")
	}

	pfxlog.Logger().Infof("new API Session Certificate: %x", sha1.Sum(certs[0].Raw))

	client.ApiSessionCertificate = certs[0]

	return nil
}

// GetServices will fetch the list of services that the identity of the current ApiSession has access to for dialing
// or binding.
func (client *CtrlClient) GetServices() ([]*rest_model.ServiceDetail, error) {
	params := service.NewListServicesParams()

	pageOffset := int64(0)
	pageLimit := int64(500)

	var services []*rest_model.ServiceDetail

	for {
		params.Limit = &pageLimit
		params.Offset = &pageOffset

		resp, err := client.ZitiEdgeClient.Service.ListServices(params, nil)

		if err != nil {
			return nil, err
		}

		if services == nil {
			services = make([]*rest_model.ServiceDetail, 0, *resp.Payload.Meta.Pagination.TotalCount)
		}

		services = append(services, resp.Payload.Data...)

		pageOffset += pageLimit
		if pageOffset >= *resp.Payload.Meta.Pagination.TotalCount {
			break
		}

		client.lastServiceRefresh = client.lastServiceUpdate
	}

	return services, nil
}

// GetServiceTerminators returns the client terminator details for a specific service.
func (client *CtrlClient) GetServiceTerminators(svc *rest_model.ServiceDetail, offset int, limit int) ([]*rest_model.TerminatorClientDetail, int, error) {
	params := service.NewListServiceTerminatorsParams()

	pageOffset := int64(offset)
	params.Offset = &pageOffset

	pageLimit := int64(limit)
	params.Limit = &pageLimit

	params.ID = *svc.ID

	resp, err := client.ZitiEdgeClient.Service.ListServiceTerminators(params, nil)

	if err != nil {
		return nil, 0, err
	}

	return resp.Payload.Data, int(*resp.Payload.Meta.Pagination.TotalCount), nil
}

// CreateSession will attempt to obtain a session token for a specific service id and type.
func (client *CtrlClient) CreateSession(id string, sessionType SessionType) (*rest_model.SessionDetail, error) {
	params := session.NewCreateSessionParams()
	params.Session = &rest_model.SessionCreate{
		ServiceID: id,
		Type:      rest_model.DialBind(sessionType),
	}

	resp, err := client.ZitiEdgeClient.Session.CreateSession(params, nil)

	if err != nil {
		return nil, err
	}

	return resp.Payload.Data, nil

}

// EnrollMfa will attempt to start TOTP MFA enrollment for the currently authenticated identity.
func (client *CtrlClient) EnrollMfa() (*rest_model.DetailMfa, error) {
	enrollMfaParams := current_identity.NewEnrollMfaParams()

	_, enrollMfaErr := client.ZitiEdgeClient.CurrentIdentity.EnrollMfa(enrollMfaParams, nil)

	if enrollMfaErr != nil {
		return nil, enrollMfaErr
	}

	detailMfaParams := current_identity.NewDetailMfaParams()
	detailMfaResp, detailMfaErr := client.ZitiEdgeClient.CurrentIdentity.DetailMfa(detailMfaParams, nil)

	if detailMfaErr != nil {
		return nil, detailMfaResp
	}

	return detailMfaResp.Payload.Data, nil
}

// VerifyMfa will complete a TOTP MFA enrollment created via EnrollMfa.
func (client *CtrlClient) VerifyMfa(code string) error {
	params := current_identity.NewVerifyMfaParams()

	params.MfaValidation = &rest_model.MfaCode{
		Code: &code,
	}

	_, err := client.ZitiEdgeClient.CurrentIdentity.VerifyMfa(params, nil)

	return err
}

// RemoveMfa will remove the currently enrolled TOTP MFA added by EnrollMfa() and verified by VerifyMfa()
func (client *CtrlClient) RemoveMfa(code string) error {
	params := current_identity.NewDeleteMfaParams()
	params.MfaValidation = &rest_model.MfaCode{
		Code: &code,
	}

	_, err := client.ZitiEdgeClient.CurrentIdentity.DeleteMfa(params, nil)

	return err
}
