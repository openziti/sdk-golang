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
	"testing"

	"github.com/openziti/sdk-golang/ziti"
)

// NewSdkContext builds an authenticated ziti.Context for id using the SDK under
// test (this tree, via the module replace directive), registering close with t.
// The identity was enrolled by the versioned CLI, so test setup never depends on
// the SDK's own enrollment; that flow has its own dedicated test.
func (h *Harness) NewSdkContext(t testing.TB, id *Identity) ziti.Context {
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

	if err := ctx.Authenticate(); err != nil {
		t.Fatalf("authenticating %s: %v", id.Name(), err)
	}
	return ctx
}
