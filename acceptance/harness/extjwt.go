/*
	Copyright NetFoundry Inc.

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

package harness

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	edgeApis "github.com/openziti/sdk-golang/v2/edge-apis"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

// ExtJwtSigner is a CI-safe, headless external JWT signer: a locally generated
// key pair registered with the controller via the versioned CLI, able to mint
// JWTs the controller will accept as a primary credential. No browser, no IdP.
type ExtJwtSigner struct {
	name     string
	id       string
	issuer   string
	audience string
	kid      string
	key      *rsa.PrivateKey
}

// Name returns the signer's unique name on the controller.
func (s *ExtJwtSigner) Name() string {
	return s.name
}

// Id returns the signer's entity id on the controller.
func (s *ExtJwtSigner) Id() string {
	return s.id
}

// MintToken signs a JWT for the given subject, accepted by this signer's
// controller registration: correct issuer, audience, kid, and lifetime.
func (s *ExtJwtSigner) MintToken(t testing.TB, subject string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": s.issuer,
		"aud": s.audience,
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	token.Header["kid"] = s.kid

	signed, err := token.SignedString(s.key)
	require.NoError(t, err, "signing ext jwt")
	return signed
}

// CreateExtJwtSigner generates a local RSA key and self-signed certificate and
// registers them as an external JWT signer via the versioned CLI, uniquely named
// per the isolation contract, with best-effort cleanup. The signer matches the
// token's sub claim against identity external ids (the CLI default).
func (h *Harness) CreateExtJwtSigner(t testing.TB, base string) *ExtJwtSigner {
	t.Helper()
	name := uniqueName(t, base)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generating signer key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "creating signer certificate")
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	kidBytes := make([]byte, 4)
	_, _ = rand.Read(kidBytes)
	signer := &ExtJwtSigner{
		name:     name,
		issuer:   "https://" + name + ".acceptance.test",
		audience: "aud-" + name,
		kid:      hex.EncodeToString(kidBytes),
		key:      key,
	}

	signer.id = strings.TrimSpace(h.Cli(t, "edge", "create", "ext-jwt-signer", name, signer.issuer,
		"--cert-pem", certPem,
		"--audience", signer.audience,
		"--kid", signer.kid))
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "ext-jwt-signer", signer.id)
	})
	return signer
}

// CreateExtJwtAuthPolicy creates an auth policy allowing the signer's JWTs as a
// primary credential, returning the policy name, uniquely named with best-effort
// cleanup.
func (h *Harness) CreateExtJwtAuthPolicy(t testing.TB, base string, signer *ExtJwtSigner) string {
	t.Helper()
	name := uniqueName(t, base)
	h.Cli(t, "edge", "create", "auth-policy", name,
		"--primary-ext-jwt-allowed",
		"--primary-ext-jwt-allowed-signers", signer.Id())
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "auth-policy", name)
	})
	return name
}

// CreateExtJwtIdentity creates an identity authenticating via the given auth
// policy with the given external id; ext-JWT identities need no enrollment.
// Returns the identity's unique name.
func (h *Harness) CreateExtJwtIdentity(t testing.TB, base, externalId, authPolicy string) string {
	t.Helper()
	name := uniqueName(t, base)
	h.Cli(t, "edge", "create", "identity", name,
		"--external-id", externalId,
		"--auth-policy", authPolicy)
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "identity", name)
	})
	return name
}

// NewExtJwtSdkContext builds an authenticated ziti.Context using jwtToken as the
// primary credential (the SDK's JwtCredentials path), registering close with t.
func (h *Harness) NewExtJwtSdkContext(t testing.TB, jwtToken string) ziti.Context {
	t.Helper()

	ctrlURL := "https://" + h.ctrl.hostPort
	caPool, err := ziti.GetControllerWellKnownCaPool(ctrlURL)
	require.NoError(t, err, "fetching controller ca pool")

	creds := edgeApis.NewJwtCredentials(jwtToken)
	creds.CaPool = caPool

	ctx, err := ziti.NewContext(&ziti.Config{
		ZtAPI:       ctrlURL + "/edge/client/v1",
		Credentials: creds,
	})
	require.NoError(t, err, "creating ext-jwt sdk context")
	t.Cleanup(ctx.Close)

	require.NoError(t, ctx.Authenticate(), "authenticating with ext jwt")
	return ctx
}
