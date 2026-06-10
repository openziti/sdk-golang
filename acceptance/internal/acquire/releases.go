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
	"fmt"
	"io"
	"net/http"
	"time"
)

// Release is a GitHub release reduced to what version resolution needs.
type Release struct {
	Tag        string
	Draft      bool
	Prerelease bool
}

// ReleaseLister lists the releases of the source repository. It is an interface so
// resolution can be unit-tested against fixtures instead of the live GitHub API.
type ReleaseLister interface {
	List(ctx context.Context) ([]Release, error)
}

const defaultGitHubBaseURL = "https://api.github.com"

// githubReleaseLister lists releases via the GitHub REST API, paginating fully.
type githubReleaseLister struct {
	org, repo, token string
	baseURL          string
	client           *http.Client
}

// NewGitHubReleaseLister returns a ReleaseLister backed by the GitHub REST API for
// org/repo. token, if non-empty, is sent as a bearer token to raise rate limits.
func NewGitHubReleaseLister(org, repo, token string) ReleaseLister {
	return &githubReleaseLister{
		org:     org,
		repo:    repo,
		token:   token,
		baseURL: defaultGitHubBaseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

type ghRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// List fetches every release page from the GitHub API and aggregates them, so a
// release on a later page is never missed.
func (g *githubReleaseLister) List(ctx context.Context) ([]Release, error) {
	var out []Release
	for page := 1; ; page++ {
		batch, err := g.listPage(ctx, page)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			out = append(out, Release{Tag: r.TagName, Draft: r.Draft, Prerelease: r.Prerelease})
		}
	}
	return out, nil
}

func (g *githubReleaseLister) listPage(ctx context.Context, page int) ([]ghRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100&page=%d", g.baseURL, g.org, g.repo, page)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing releases (page %d): %w", page, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("listing releases (page %d): unexpected status %s: %s", page, resp.Status, body)
	}

	var batch []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, fmt.Errorf("decoding releases (page %d): %w", page, err)
	}
	return batch, nil
}
