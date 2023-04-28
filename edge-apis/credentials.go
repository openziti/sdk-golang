package edge_apis

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/ziti/sdkinfo"
	"net/http"
)

// Credentials represents the minimal information needed across all authentication mechanisms to authenticate an identity
// to an OpenZiti network.
type Credentials interface {
	//Payload constructs the objects that represent the JSON authentication payload for this set of credentials.
	Payload() *rest_model.Authenticate

	//TlsCerts returns zero or more tls.Certificates used for client authentication.
	TlsCerts() []tls.Certificate

	//GetCaPool will return the CA pool that this credential was configured to trust.
	GetCaPool() *x509.CertPool

	//Method return the authentication necessary to complete an authentication request.
	Method() string

	//ClientAuthInfoWriter is used to pass a Credentials instance to the openapi runtime to authenticate outgoing
	//requests.
	runtime.ClientAuthInfoWriter
}

// IdentityProvider is a sentinel interface used to determine whether the backing Credentials instance can provide
// an Identity that can provide a certificate and private key used to initiate mTLS connections.
type IdentityProvider interface {
	GetIdentity() identity.Identity
}

// toTlsCerts converts an array of certificates into a single tls.Certificate. Index zero is assumed to be the leaf
// certificate and all subsequent certificates to be the support certificate chain that should be sent to servers.
// At least one certificate must be provided.
func toTlsCerts(certs []*x509.Certificate, key crypto.PrivateKey) tls.Certificate {
	tlsCert := tls.Certificate{
		PrivateKey: key,
		Leaf:       certs[0],
	}
	for _, cert := range certs {
		tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	}

	return tlsCert
}

// getClientAuthInfoOp returns a one-off runtime.ClientOperation used to authenticate single requests without altering
// the authentication operation of the entire client runtime.
func getClientAuthInfoOp(credentials Credentials, client *http.Client) func(*runtime.ClientOperation) {
	return func(operation *runtime.ClientOperation) {
		operation.AuthInfo = credentials

		certs := credentials.TlsCerts()
		if len(certs) != 0 {
			operation.Client = client
			if transport, ok := operation.Client.Transport.(*http.Transport); ok {
				transport.TLSClientConfig.Certificates = certs
			}
		}
	}
}

// BaseCredentials is a shared struct of information all Credentials implementations require.
type BaseCredentials struct {
	//ConfigTypes is used to set the configuration types for services during authentication
	ConfigTypes []string

	//EnvInfo is provided during authentication to set environmental information about the client.
	EnvInfo *rest_model.EnvInfo

	//SdkInfo is provided during authentication to set SDK information about the client.
	SdkInfo *rest_model.SdkInfo

	//CaPool will override the client's default certificate pool if set to a non-nil value.
	CaPool *x509.CertPool
}

// Payload will produce the object used to construct the body of an authentication requests. The base version
// sets shared information available in BaseCredentials.
func (self *BaseCredentials) Payload() *rest_model.Authenticate {
	envInfo, sdkInfo := sdkinfo.GetSdkInfo()

	if self.EnvInfo != nil {
		envInfo = self.EnvInfo
	}

	if self.SdkInfo != nil {
		sdkInfo = self.SdkInfo
	}

	return &rest_model.Authenticate{
		ConfigTypes: self.ConfigTypes,
		EnvInfo:     envInfo,
		SdkInfo:     sdkInfo,
	}
}

// GetCaPool provides a base implementation to return the certificate pool of a Credentials instance.
func (c *BaseCredentials) GetCaPool() *x509.CertPool {
	return c.CaPool
}

// AuthenticateRequest provides a base implementation to authenticate an outgoing request. This is provided here
// for authentication methods such as `cert` which do not have to provide any more request level information.
func (c *BaseCredentials) AuthenticateRequest(_ runtime.ClientRequest, _ strfmt.Registry) error {
	return nil
}

// TlsCerts provides a base implementation of returning the tls.Certificate array that will be used to setup
// mTLS connections. This is provided here for authentication methods that do not initially require mTLS (e.g. JWTs).
func (self *BaseCredentials) TlsCerts() []tls.Certificate {
	return nil
}

var _ Credentials = &CertCredentials{}

// CertCredentials represents authentication using certificates that are not from an Identity configuration file.
type CertCredentials struct {
	BaseCredentials
	Certs []*x509.Certificate
	Key   crypto.PrivateKey
}

// NewCertCredentials creates Credentials instance based upon an array of certificates. At least one certificate must
// be provided and the certificate at index zero is assumed to be the leaf client certificate that pairs with the
// provided private key. All other certificates are assumed to support the leaf client certificate as a chain.
func NewCertCredentials(certs []*x509.Certificate, key crypto.PrivateKey) *CertCredentials {
	return &CertCredentials{
		BaseCredentials: BaseCredentials{},
		Certs:           certs,
		Key:             key,
	}
}

func (c *CertCredentials) Method() string {
	return "cert"
}

func (c *CertCredentials) TlsCerts() []tls.Certificate {
	return []tls.Certificate{toTlsCerts(c.Certs, c.Key)}
}

func (c *CertCredentials) GetIdentity() identity.Identity {
	return identity.NewClientTokenIdentityWithPool(c.Certs, c.Key, c.GetCaPool())
}

var _ Credentials = &IdentityCredentials{}

type IdentityCredentials struct {
	BaseCredentials
	Identity identity.Identity
}

// NewIdentityCredentials creates a Credentials instance based upon and Identity.
func NewIdentityCredentials(identity identity.Identity) *IdentityCredentials {
	return &IdentityCredentials{
		BaseCredentials: BaseCredentials{},
		Identity:        identity,
	}
}

// NewIdentityCredentialsFromConfig creates a Credentials instance based upon and Identity configuration.
func NewIdentityCredentialsFromConfig(config identity.Config) *IdentityCredentials {
	return &IdentityCredentials{
		BaseCredentials: BaseCredentials{},
		Identity:        &identity.LazyIdentity{Config: &config},
	}
}

func (c *IdentityCredentials) GetIdentity() identity.Identity {
	return c.Identity
}

func (c *IdentityCredentials) Method() string {
	return "cert"
}

func (c *IdentityCredentials) GetCaPool() *x509.CertPool {
	return c.Identity.CA()
}

func (c *IdentityCredentials) TlsCerts() []tls.Certificate {
	tlsCert := c.Identity.Cert()

	if tlsCert != nil {
		return []tls.Certificate{*tlsCert}
	}
	return nil
}

var _ Credentials = &JwtCredentials{}

type JwtCredentials struct {
	BaseCredentials
	JWT                string
	SendOnEveryRequest bool
}

// NewJwtCredentials creates a Credentials instance based on a JWT obtained from an outside system.
func NewJwtCredentials(jwt string) *JwtCredentials {
	return &JwtCredentials{
		BaseCredentials: BaseCredentials{},
		JWT:             jwt,
	}
}

func (c *JwtCredentials) Method() string {
	return "ext-jwt"
}

func (c *JwtCredentials) AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error {
	return request.SetHeaderParam("Authorization", "Bearer "+c.JWT)
}

var _ Credentials = &DualAuthCredentials{}

type DualAuthCredentials struct {
	BaseCredentials
	Identity identity.Identity
	JWT      string
}

// NewDualAuthCredentials creates a Credentials instance based on Identity with JWT string added.
func NewDualAuthCredentials(config identity.Config, jwt string) *DualAuthCredentials {
	return &DualAuthCredentials{
		BaseCredentials: BaseCredentials{},
		Identity:        &identity.LazyIdentity{Config: &config},
		JWT:             jwt,
	}
}

func (c *DualAuthCredentials) Method() string {
	return "cert"
}

func (c *DualAuthCredentials) GetCaPool() *x509.CertPool {
	return c.Identity.CA()
}

func (c *DualAuthCredentials) TlsCerts() []tls.Certificate {
	tlsCert := c.Identity.Cert()

	if tlsCert != nil {
		return []tls.Certificate{*tlsCert}
	}
	return nil
}

func (c *DualAuthCredentials) AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error {
	return request.SetHeaderParam("Authorization", "Bearer "+c.JWT)
}

var _ Credentials = &UpdbCredentials{}

type UpdbCredentials struct {
	BaseCredentials
	Username string
	Password string
}

func (self *UpdbCredentials) Method() string {
	return "password"
}

// NewUpdbCredentials creates a Credentials instance based on a username/passwords combination.
func NewUpdbCredentials(username string, password string) *UpdbCredentials {
	return &UpdbCredentials{
		BaseCredentials: BaseCredentials{},
		Username:        username,
		Password:        password,
	}
}

func (self *UpdbCredentials) Payload() *rest_model.Authenticate {
	payload := self.BaseCredentials.Payload()
	payload.Username = rest_model.Username(self.Username)
	payload.Password = rest_model.Password(self.Password)

	return payload
}
