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
	"os"
	"testing"

	edgeApis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
)

// NewSdkContext builds an authenticated ziti.Context for id using the SDK under
// test (this tree, via the module replace directive), registering close with t.
// The identity was enrolled by the versioned CLI, so test setup never depends on
// the SDK's own enrollment; that flow has its own dedicated test.
func (h *Harness) NewSdkContext(t testing.TB, id *Identity) ziti.Context {
	t.Helper()
	return h.newSdkContext(t, id, false)
}

// NewLegacySdkContext is NewSdkContext with OIDC disabled, forcing the legacy
// authentication path, for tests exercising the legacy/OIDC split.
func (h *Harness) NewLegacySdkContext(t testing.TB, id *Identity) ziti.Context {
	t.Helper()
	return h.newSdkContext(t, id, true)
}

func (h *Harness) newSdkContext(t testing.TB, id *Identity, forceLegacy bool) ziti.Context {
	t.Helper()

	cfg, err := ziti.NewConfigFromFile(id.ConfigPath())
	if err != nil {
		t.Fatalf("loading identity config %s: %v", id.ConfigPath(), err)
	}

	ctx, err := ziti.NewContext(cfg)
	if err != nil {
		t.Fatalf("creating sdk context for %s: %v", id.Name(), err)
	}
	t.Cleanup(ctx.Close)

	if forceLegacy {
		impl := ctx.(*ziti.ContextImpl)
		impl.CtrlClt.SetAllowOidcDynamicallyEnabled(false)
		impl.CtrlClt.SetUseOidc(false)
	}

	if err := ctx.Authenticate(); err != nil {
		t.Fatalf("authenticating %s: %v", id.Name(), err)
	}
	return ctx
}

// ApiSessionType reports the type (legacy vs oidc) of the context's current API
// session.
func ApiSessionType(t testing.TB, ctx ziti.Context) edgeApis.ApiSessionType {
	t.Helper()
	apiSession := ctx.(*ziti.ContextImpl).CtrlClt.GetCurrentApiSession()
	if apiSession == nil {
		t.Fatal("context has no current api session")
	}
	return apiSession.GetType()
}

// RouterSupportsConnectV2 reports whether the named router's connection, as seen
// by ctx, advertises ConnectV2. This is handshake state, independent of which
// dial path any dial took, so a test can compute the expected protocol and check
// it against the observed dial event. The context must have connected to the
// router (e.g. by dialing) first.
func RouterSupportsConnectV2(t testing.TB, ctx ziti.Context, routerName string) bool {
	t.Helper()
	insp := ctx.(*ziti.ContextImpl).Inspect()
	for _, rc := range insp.RouterConnections {
		if rc.RouterName == routerName {
			return rc.SupportsConnectV2
		}
	}
	t.Fatalf("context has no router connection to %s", routerName)
	return false
}

// RequireV2Env when "true", switches the dial-negotiation coverage to required
// mode: the environment must actually exercise ConnectV2 (capable router, OIDC
// session), and absence is a failure rather than an adaptive V1 pass. The
// designated CI coverage job sets this; see the design's V2 coverage invariant.
const RequireV2Env = "ZITI_ACCEPTANCE_REQUIRE_V2"

// RequireV2 reports whether required-mode V2 coverage is enabled.
func RequireV2() bool {
	return os.Getenv(RequireV2Env) == "true"
}
