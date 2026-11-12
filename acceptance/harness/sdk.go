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

	edgeApis "github.com/openziti/sdk-golang/v2/edge-apis"
	"github.com/openziti/sdk-golang/v2/ziti"
)

// NewSdkContext builds an authenticated ziti.Context for id using the SDK under
// test (this tree, via the module replace directive), registering close with tb.
// The identity was enrolled by the versioned CLI, so test setup never depends on
// the SDK's own enrollment; that flow has its own dedicated test.
func (h *Harness) NewSdkContext(tb testing.TB, id *Identity) ziti.Context {
	tb.Helper()
	return h.newSdkContext(tb, id, false, nil)
}

// NewSdkContextWithOptions is NewSdkContext with the given context options. Fields
// left zero are not defaulted, so start from a copy of *ziti.DefaultOptions.
func (h *Harness) NewSdkContextWithOptions(tb testing.TB, id *Identity, options *ziti.Options) ziti.Context {
	tb.Helper()
	return h.newSdkContext(tb, id, false, options)
}

// NewLegacySdkContext is NewSdkContext with OIDC disabled, forcing the legacy
// authentication path, for tests exercising the legacy/OIDC split.
func (h *Harness) NewLegacySdkContext(tb testing.TB, id *Identity) ziti.Context {
	tb.Helper()
	return h.newSdkContext(tb, id, true, nil)
}

// NewSdkContextWithConfigTypes is NewSdkContext that also requests the given
// service config types, so the context populates per-service config (e.g.
// intercept.v1) used by GetServiceForAddr/DialAddr.
func (h *Harness) NewSdkContextWithConfigTypes(tb testing.TB, id *Identity, configTypes ...string) ziti.Context {
	tb.Helper()

	cfg, err := ziti.NewConfigFromFile(id.ConfigPath())
	if err != nil {
		tb.Fatalf("loading identity config %s: %v", id.ConfigPath(), err)
	}
	cfg.ConfigTypes = append(cfg.ConfigTypes, configTypes...)

	ctx, err := ziti.NewContext(cfg)
	if err != nil {
		tb.Fatalf("creating sdk context for %s: %v", id.Name(), err)
	}
	tb.Cleanup(ctx.Close)

	if err := ctx.Authenticate(); err != nil {
		tb.Fatalf("authenticating %s: %v", id.Name(), err)
	}
	return ctx
}

func (h *Harness) newSdkContext(tb testing.TB, id *Identity, forceLegacy bool, options *ziti.Options) ziti.Context {
	tb.Helper()

	cfg, err := ziti.NewConfigFromFile(id.ConfigPath())
	if err != nil {
		tb.Fatalf("loading identity config %s: %v", id.ConfigPath(), err)
	}

	ctx, err := ziti.NewContextWithOpts(cfg, options)
	if err != nil {
		tb.Fatalf("creating sdk context for %s: %v", id.Name(), err)
	}
	tb.Cleanup(ctx.Close)

	if forceLegacy {
		impl := ctx.(*ziti.ContextImpl)
		impl.CtrlClt.SetAllowOidcDynamicallyEnabled(false)
		impl.CtrlClt.SetUseOidc(false)
	}

	if err := ctx.Authenticate(); err != nil {
		tb.Fatalf("authenticating %s: %v", id.Name(), err)
	}
	return ctx
}

// ApiSessionType reports the type (legacy vs oidc) of the context's current API
// session.
func ApiSessionType(tb testing.TB, ctx ziti.Context) edgeApis.ApiSessionType {
	tb.Helper()
	apiSession := ctx.(*ziti.ContextImpl).CtrlClt.GetCurrentApiSession()
	if apiSession == nil {
		tb.Fatal("context has no current api session")
	}
	return apiSession.GetType()
}

// RouterSupportsConnectV2 reports whether the named router's connection, as seen
// by ctx, advertises ConnectV2. This is handshake state, independent of which
// dial path any dial took, so a test can compute the expected protocol and check
// it against the observed dial event. The context must have connected to the
// router (e.g. by dialing) first.
func RouterSupportsConnectV2(tb testing.TB, ctx ziti.Context, routerName string) bool {
	tb.Helper()
	insp := ctx.(*ziti.ContextImpl).Inspect()
	for _, rc := range insp.RouterConnections {
		if rc.RouterName == routerName {
			return rc.SupportsConnectV2
		}
	}
	tb.Fatalf("context has no router connection to %s", routerName)
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
