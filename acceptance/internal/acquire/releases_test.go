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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	require.NoError(t, json.NewEncoder(w).Encode(v))
}

// newPagedReleaseServer serves the given pages (1-indexed) of releases as the GitHub
// API would, returning an empty array past the last page.
func newPagedReleaseServer(t *testing.T, pages [][]ghRelease) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if p := r.URL.Query().Get("page"); p == "2" {
			page = 2
		} else if p != "" && p != "1" {
			page = 99
		}
		w.Header().Set("Content-Type", "application/json")
		if page >= 1 && page <= len(pages) {
			writeJSON(t, w, pages[page-1])
			return
		}
		writeJSON(t, w, []ghRelease{})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func githubListerFor(srv *httptest.Server) *githubReleaseLister {
	return &githubReleaseLister{
		org:     "openziti",
		repo:    "ziti",
		baseURL: srv.URL,
		client:  srv.Client(),
	}
}

func TestGitHubListerPaginates(t *testing.T) {
	srv := newPagedReleaseServer(t, [][]ghRelease{
		{{TagName: "v1.6.16"}, {TagName: "v1.6.17"}, {TagName: "v2.0.7"}},
		{{TagName: "v2.0.8"}, {TagName: "v2.0.9"}}, // higher 2.0 patches only on page 2
	})
	rels, err := githubListerFor(srv).List(context.Background())
	require.NoError(t, err)
	require.Len(t, rels, 5)

	tags := make(map[string]bool, len(rels))
	for _, r := range rels {
		tags[r.Tag] = true
	}
	require.True(t, tags["v2.0.9"], "release on page 2 must be aggregated")
}

// TestResolveWildcardAcrossPages proves resolution sees releases beyond the first
// page: the highest 2.0 patch (v2.0.9) lives only on page 2.
func TestResolveWildcardAcrossPages(t *testing.T) {
	srv := newPagedReleaseServer(t, [][]ghRelease{
		{{TagName: "v1.6.17"}, {TagName: "v2.0.7"}},
		{{TagName: "v2.0.8"}, {TagName: "v2.0.9"}},
	})
	cfg := testCfg()
	spec, err := ParseSpec("active-lts", cfg)
	require.NoError(t, err)
	id, err := ResolveTag(context.Background(), spec, cfg, githubListerFor(srv))
	require.NoError(t, err)
	require.Equal(t, "v2.0.9", id.Tag)
}

func TestGitHubListerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	_, err := githubListerFor(srv).List(context.Background())
	require.Error(t, err)
}
