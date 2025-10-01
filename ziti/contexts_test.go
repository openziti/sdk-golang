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

package ziti

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/openziti/identity"
	edgeapis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/stretchr/testify/require"
)

func Test_NewContext(t *testing.T) {

	t.Run("creating a new context with no identity config and no credentials does not error", func(t *testing.T) {
		req := require.New(t)

		cfg := &Config{
			ZtAPI: "https://example.com:1234",
		}

		ztx, err := NewContext(cfg)
		req.NoError(err)
		req.NotNil(ztx)
	})

	t.Run("creating a new context with identity config and no credentials creates identity credentials", func(t *testing.T) {
		req := require.New(t)

		idTestCert, err := newTestSelfSignedCert("test123", nil, 1*time.Hour)

		req.NoError(err)
		req.NotNil(idTestCert)

		expectedCertPem := string(idTestCert.CertPEM)
		expectedKeyPem := string(idTestCert.KeyPEM)

		idConfig := identity.Config{
			Cert: "pem:" + expectedCertPem,
			Key:  "pem:" + expectedKeyPem,
		}

		cfg := &Config{
			ZtAPI: "https://example.com:1234",
			ID:    idConfig,
		}

		ztx, err := NewContext(cfg)
		req.NoError(err)
		req.NotNil(ztx)

		ztxImpl, ok := ztx.(*ContextImpl)
		req.True(ok)
		req.NotNil(ztxImpl)

		clientIdentityCreds, ok := ztxImpl.CtrlClt.Credentials.(*edgeapis.IdentityCredentials)
		req.True(ok)
		req.NotNil(clientIdentityCreds)

		clientIdentityTslCert := clientIdentityCreds.Identity.Cert()
		req.NotNil(clientIdentityTslCert)

		req.Equal(idTestCert.Cert.Raw, clientIdentityTslCert.Certificate[0])
		req.Equal(idTestCert.PrivateKey, clientIdentityTslCert.PrivateKey)
	})

	t.Run("creating a new context with credentials uses credentials", func(t *testing.T) {
		req := require.New(t)

		certCredentialsCert, err := newTestSelfSignedCert("testCert", nil, 1*time.Hour)
		req.NoError(err)
		req.NotNil(certCredentialsCert)

		certPool := x509.NewCertPool()
		certCreds := edgeapis.NewCertCredentials([]*x509.Certificate{certCredentialsCert.Cert}, certCredentialsCert.PrivateKey)
		certCreds.CaPool = certPool

		cfg := &Config{
			ZtAPI:       "https://example.com:1234",
			Credentials: certCreds,
		}

		ztx, err := NewContext(cfg)
		req.NoError(err)
		req.NotNil(ztx)

		ztxImpl, ok := ztx.(*ContextImpl)
		req.True(ok)
		req.NotNil(ztxImpl)

		req.Equal(certCreds, ztxImpl.CtrlClt.Credentials)
		req.Equal(certPool, ztxImpl.CtrlClt.CaPool)
	})

	t.Run("creating a new context with identity config and credentials, uses credentials", func(t *testing.T) {
		req := require.New(t)

		idConfigCert, err := newTestSelfSignedCert("testIdConfigCert", nil, 1*time.Hour)
		req.NoError(err)
		req.NotNil(idConfigCert)

		idConfigCertPem := string(idConfigCert.CertPEM)
		idConfigKeyPem := string(idConfigCert.KeyPEM)

		idConfig := identity.Config{
			Cert: "pem:" + idConfigCertPem,
			Key:  "pem:" + idConfigKeyPem,
		}

		certCredentialsCert, err := newTestSelfSignedCert("testCertCredentialsCert", nil, 1*time.Hour)
		req.NoError(err)
		req.NotNil(certCredentialsCert)

		certPool := x509.NewCertPool()
		certCreds := edgeapis.NewCertCredentials([]*x509.Certificate{certCredentialsCert.Cert}, certCredentialsCert.PrivateKey)
		certCreds.CaPool = certPool

		cfg := &Config{
			ZtAPI:       "https://example.com:1234",
			Credentials: certCreds,
			ID:          idConfig,
		}

		ztx, err := NewContext(cfg)
		req.NoError(err)
		req.NotNil(ztx)

		ztxImpl, ok := ztx.(*ContextImpl)
		req.True(ok)
		req.NotNil(ztxImpl)

		req.Equal(certCreds, ztxImpl.CtrlClt.Credentials)
		req.Equal(certPool, ztxImpl.CtrlClt.CaPool)
	})
}

type testCert struct {
	Cert       *x509.Certificate
	PrivateKey crypto.PrivateKey
	CertPEM    []byte
	KeyPEM     []byte
}

func newTestSelfSignedCert(commonName string, hosts []string, ttl time.Duration) (*testCert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else if h != "" {
			dnsNames = append(dnsNames, h)
		}
	}

	notBefore := time.Now().Add(-1 * time.Minute)
	notAfter := notBefore.Add(ttl)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return &testCert{
		Cert:       cert,
		PrivateKey: priv,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
	}, nil
}
