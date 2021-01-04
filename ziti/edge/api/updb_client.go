package api

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Jeffail/gabs"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/common/constants"
	"github.com/openziti/foundation/identity/certtools"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/sdk-golang/ziti/edge"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"
)

type updbClient struct {
	*ctrlClient
	initDone  sync.Once
	ztApi     string
	username  string
	password  string
	postInit  func(ctrlClient Client) error
	tlsConfig *tls.Config
	identity  *UpdbIdentity
}

func NewUpdbClient(ztApi, username, password string, tlsConfig *tls.Config, postIniti func(ctrlClient Client) error) *updbClient {
	client := &updbClient{
		username:  username,
		password:  password,
		postInit:  postIniti,
		ztApi:     ztApi,
		tlsConfig: tlsConfig,
	}

	return client
}

func (c *updbClient) Initialize() error {
	var err error
	c.initDone.Do(func() {
		err = c.load()
	})

	if c.postInit != nil {
		return c.postInit(c)
	}
	return err
}

func (c *updbClient) load() error {
	zitiUrl, _ := url.Parse(c.ztApi)

	var err error

	c.ctrlClient, err = NewClient(zitiUrl, c.tlsConfig)

	c.authUrl = c.zitiUrl.ResolveReference(updbAuthUrl).String()

	return err
}

type UpdbIdentity struct {
	cert       *x509.Certificate
	privateKey crypto.PrivateKey
	caCerts    []*x509.Certificate
	caPool     *x509.CertPool
}

func NewUpdbIdentity(cert *x509.Certificate, key crypto.PrivateKey, caCerts []*x509.Certificate) (*UpdbIdentity, error) {
	caPool := x509.NewCertPool()

	for _, caCert := range caCerts {
		caPool.AddCert(caCert)
	}

	return &UpdbIdentity{
		cert:       cert,
		privateKey: key,
		caCerts:    caCerts,
		caPool:     caPool,
	}, nil
}

func (u UpdbIdentity) Cert() *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{u.cert.Raw}, PrivateKey: u.privateKey, Leaf: u.cert}
}

func (u UpdbIdentity) ServerCert() *tls.Certificate {
	return nil
}

func (u UpdbIdentity) CA() *x509.CertPool {
	return u.caPool
}

func (u UpdbIdentity) ServerTLSConfig() *tls.Config {
	return nil
}

func (u UpdbIdentity) ClientTLSConfig() *tls.Config {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*u.Cert()},
		RootCAs:      u.caPool,
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}

func (c *updbClient) GetIdentity() identity.Identity {
	//call CreateSessionCertificate() first
	if c.identity == nil {
		c.CreateSessionCertificate()
	}

	return c.identity
}

func (c *updbClient) Login(info map[string]interface{}, configTypes []string) (*edge.ApiSession, error) {
	info["username"] = c.username
	info["password"] = c.password

	return c.ctrlClient.Login(info, configTypes)
}

func (c *updbClient) CreateSessionCertificate() (*x509.Certificate, crypto.PrivateKey, error) {

	csr, pk, err := generateCsr()
	if err != nil {
		return nil, nil, err
	}

	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	body := gabs.New()
	body.Set(string(csrPem), "csr")
	bodyBytes := body.Bytes()
	reqBody := bytes.NewBuffer(bodyBytes)

	fullCurrentApiSessionCertUrl := c.zitiUrl.ResolveReference(sessionCertUrl).String()

	req, _ := http.NewRequest("POST", fullCurrentApiSessionCertUrl, reqBody)
	req.Header.Set(constants.ZitiSession, c.apiSession.Token)
	req.Header.Set("content-type", "application/json")

	resp, err := c.clt.Do(req)

	if err != nil {
		return nil, nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, nil, fmt.Errorf("could not read response body creating API Session Certificate: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, nil, fmt.Errorf("could not create API Session certificate: %s", respBody)
	}

	respJson, err := gabs.ParseJSON(respBody)

	if err != nil {
		return nil, nil, fmt.Errorf("could not parse response body creating API Session Certificate: %v", err)
	}

	pemCert, ok := respJson.Path("data.certificate").Data().(string)

	if !ok {
		return nil, nil, errors.New("[certificate] property not found in API Session Certificate response")
	}

	certs, err := certtools.LoadCert([]byte(pemCert))

	if err != nil {
		return nil, nil, fmt.Errorf("could not parse certificate PEM in API Session Certificate create response: %v", err)
	}

	if len(certs) == 0 {
		return nil, nil, errors.New("no certificates found after parsing PEM response from API Session Certificate create")
	}

	caPems, _ := respJson.Path("data.cas").Data().(string)

	caCerts, _ := certtools.LoadCert([]byte(caPems))

	c.identity, err = NewUpdbIdentity(certs[0], pk, caCerts)

	if err != nil {
		return nil, nil, err
	}

	return certs[0], pk, nil
}

func generateCsr() ([]byte, crypto.PrivateKey, error) {
	p384 := elliptic.P384()
	pfxlog.Logger().Infof("generating %s EC key", p384.Params().Name)
	privateKey, err := ecdsa.GenerateKey(p384, rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	hostname, err := os.Hostname()

	if err != nil {
		return nil, nil, err
	}

	request, err := certtools.NewCertRequest(map[string]string{
		"C": "US", "O": "GOSDK", "CN": hostname,
	}, nil)

	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, request, privateKey)

	if err != nil {
		return nil, nil, err
	}

	return csr, privateKey, nil
}
