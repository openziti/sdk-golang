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

package acquire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func testCfg() Versions {
	return Versions{
		Labels: map[string]string{"active-lts": "v2.0.x", "maint-lts": "v1.6.17"},
		Source: Source{Org: "openziti", Repo: "ziti"},
	}
}

func TestParseSpec(t *testing.T) {
	cfg := testCfg()
	tests := []struct {
		value     string
		wantKind  SpecKind
		wantLabel string
	}{
		{"latest", SpecLabel, "latest"},
		{"active-lts", SpecLabel, "active-lts"},
		{"maint-lts", SpecLabel, "maint-lts"},
		{"v1.6.17", SpecReleaseVersion, ""},
		{"v2.0.7", SpecReleaseVersion, ""},
		{"v2.1.0-rc1", SpecReleaseVersion, ""},
		{"connect-v2", SpecGitRef, ""},
		{"main", SpecGitRef, ""},
		{"a1b2c3d4e5f60718293a4b5c6d7e8f9001122334", SpecGitRef, ""}, // SHA
		{"v2.0.x", SpecGitRef, ""},                                   // raw wildcard isn't a direct selector
		{"v1.6", SpecGitRef, ""},                                     // not a full release version
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			spec, err := ParseSpec(tc.value, cfg)
			require.NoError(t, err)
			require.Equal(t, tc.wantKind, spec.Kind, "kind for %q", tc.value)
			require.Equal(t, tc.value, spec.Raw)
			require.Equal(t, tc.wantLabel, spec.Label)
		})
	}
}

func TestParseSpecEmpty(t *testing.T) {
	_, err := ParseSpec("", testCfg())
	require.Error(t, err)
}
