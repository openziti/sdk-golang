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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeLister returns a fixed release set, deliberately unsorted and salted with
// drafts and prereleases.
type fakeLister struct {
	rels []Release
	err  error
}

func (f fakeLister) List(context.Context) ([]Release, error) { return f.rels, f.err }

// fixtureReleases is intentionally out of order and mixes a v-prefix, drafts, and
// prereleases so resolution cannot rely on API ordering.
func fixtureReleases() []Release {
	return []Release{
		{Tag: "v1.6.16"},
		{Tag: "v2.0.7"},
		{Tag: "v2.1.0-rc1", Prerelease: true}, // prerelease: excluded from latest/wildcard
		{Tag: "v2.0.9-draft", Draft: true},     // draft: excluded everywhere
		{Tag: "v1.6.17"},
		{Tag: "v2.0.8"},
		{Tag: "v2.1.0", Draft: true}, // a higher core but draft -> must not win latest
		{Tag: "not-a-version"},        // ignored by semver selection
	}
}

func TestResolveTag(t *testing.T) {
	cfg := testCfg()
	lister := fakeLister{rels: fixtureReleases()}
	ctx := context.Background()

	tests := []struct {
		name    string
		value   string
		wantTag string
	}{
		{"latest skips drafts and prereleases", "latest", "v2.0.8"},
		{"active-lts wildcard picks highest 2.0 patch", "active-lts", "v2.0.8"},
		{"maint-lts pinned tag", "maint-lts", "v1.6.17"},
		{"explicit release version", "v2.0.7", "v2.0.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ParseSpec(tc.value, cfg)
			require.NoError(t, err)
			id, err := ResolveTag(ctx, spec, cfg, lister)
			require.NoError(t, err)
			require.Equal(t, tc.wantTag, id.Tag)
		})
	}
}

func TestResolveTagExplicitMissing(t *testing.T) {
	cfg := testCfg()
	spec, err := ParseSpec("v9.9.9", cfg)
	require.NoError(t, err)
	_, err = ResolveTag(context.Background(), spec, cfg, fakeLister{rels: fixtureReleases()})
	require.Error(t, err)
}

func TestResolveTagGitRefBuildsFromSource(t *testing.T) {
	cfg := testCfg()
	spec, err := ParseSpec("connect-v2", cfg)
	require.NoError(t, err)
	_, err = ResolveTag(context.Background(), spec, cfg, fakeLister{rels: fixtureReleases()})
	require.ErrorIs(t, err, ErrBuildFromSource)
}

func TestResolveTagWildcardNoMatch(t *testing.T) {
	cfg := Versions{
		Labels: map[string]string{"active-lts": "v3.0.x"}, // no 3.0.x in fixtures
		Source: Source{Org: "openziti", Repo: "ziti"},
	}
	spec, err := ParseSpec("active-lts", cfg)
	require.NoError(t, err)
	_, err = ResolveTag(context.Background(), spec, cfg, fakeLister{rels: fixtureReleases()})
	require.Error(t, err)
}
