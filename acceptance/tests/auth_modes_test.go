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

//go:build acceptance

package tests

import (
	"testing"
	"time"

	edgeApis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/acceptance/harness"
	"github.com/stretchr/testify/require"
)

// Test_AuthModes_OidcAndLegacy is half of P0 #3: the SDK dials successfully under
// both auth modes — OIDC (the default where the controller supports it) and
// legacy (forced via SetUseOidc(false)) — with the session type asserted, not
// assumed.
func Test_AuthModes_OidcAndLegacy(t *testing.T) {
	h := shared
	r := h.DefaultRouter()

	hostID := h.CreateIdentity(t, "host")
	oidcID := h.CreateIdentity(t, "oidc-client")
	legacyID := h.CreateIdentity(t, "legacy-client")
	svc := h.CreateService(t, "echo")

	h.GrantBind(t, svc, hostID)
	h.GrantDial(t, svc, oidcID, legacyID)
	h.GrantRouterAccess(t, r, hostID, oidcID, legacyID)
	h.GrantServiceRouterAccess(t, svc, r)

	hostCtx := h.NewSdkContext(t, hostID)
	startEchoServer(t, hostCtx, svc.Name())

	oidcCtx := h.NewSdkContext(t, oidcID)
	require.Equal(t, edgeApis.ApiSessionTypeOidc, harness.ApiSessionType(t, oidcCtx),
		"both supported lines speak OIDC, so the default must negotiate it")
	requireEchoRoundTrip(t, oidcCtx, svc.Name(), "hello over oidc")

	legacyCtx := h.NewLegacySdkContext(t, legacyID)
	require.Equal(t, edgeApis.ApiSessionTypeLegacy, harness.ApiSessionType(t, legacyCtx),
		"SetUseOidc(false) must force the legacy session path")
	requireEchoRoundTrip(t, legacyCtx, svc.Name(), "hello over legacy")
}

// Test_AuthModes_ExtJwtPrimary is the other half of P0 #3: ext-JWT as a primary
// credential, fully headless — a locally generated signer registered via the CLI,
// a locally minted JWT, and the SDK's JwtCredentials path. The helper asserts the
// authenticated identity matches the one the test intended, so a signer or
// auth-policy mapping mistake fails here, not as a confusing downstream error.
func Test_AuthModes_ExtJwtPrimary(t *testing.T) {
	h := shared

	signer := h.CreateExtJwtSigner(t, "signer")
	authPolicy := h.CreateExtJwtAuthPolicy(t, "extjwt", signer)
	externalId := "ext-" + signer.Name()
	identityName := h.CreateExtJwtIdentity(t, "jwt-user", externalId, authPolicy)

	token := signer.MintToken(t, externalId, time.Hour)
	ctx := h.NewExtJwtSdkContext(t, token)

	current, err := ctx.GetCurrentIdentity()
	require.NoError(t, err)
	require.NotNil(t, current.Name)
	require.Equal(t, identityName, *current.Name,
		"the JWT's sub must map to the intended identity via its external id")

	// the SDK's signer enumeration must include our signer
	signers, err := ctx.GetExternalSigners()
	require.NoError(t, err)
	names := make([]string, 0, len(signers))
	for _, s := range signers {
		if s.Name != nil {
			names = append(names, *s.Name)
		}
	}
	require.Contains(t, names, signer.Name())
}
