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

package harness

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_ControllerBringUp is the per-version bootstrap contract check: the selected
// ziti binary's `quickstart --no-router` must yield an admin-usable, controller-only
// process. Run with -tags acceptance; ZITI_ACCEPTANCE_VERSION selects the version.
func Test_ControllerBringUp(t *testing.T) {
	h := Start(t)

	require.NotEmpty(t, h.Version().String())
	t.Logf("testing against ziti %s at %s", h.Version(), h.ControllerHostPort())

	// the admin identity's display name varies by line ("Default Admin" on 1.6,
	// "admin" on 2.x), so assert version-agnostically that it's listed
	out := h.Cli(t, "edge", "list", "identities")
	require.Contains(t, strings.ToLower(out), "admin")
	require.Contains(t, out, "results: 1-")
}
