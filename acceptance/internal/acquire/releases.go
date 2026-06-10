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

// Asset is a downloadable artifact attached to a release.
type Asset struct {
	Name        string
	DownloadURL string
}

// ReleaseDetail is a single release with its downloadable assets.
type ReleaseDetail struct {
	Tag    string
	Assets []Asset
}

// ReleaseLister lists the releases of the source repository. It is an interface so
// resolution can be unit-tested against fixtures instead of the live GitHub API.
type ReleaseLister interface {
	List(ctx context.Context) ([]Release, error)
}

// ReleaseSource extends ReleaseLister with asset lookup and download, the full
// surface binary acquisition needs.
type ReleaseSource interface {
	ReleaseLister
	// FindRelease returns the release for tag with its assets.
	FindRelease(ctx context.Context, tag string) (*ReleaseDetail, error)
	// Download streams the asset at url to dst.
	Download(ctx context.Context, url string, dst io.Writer) error
}

const defaultGitHubBaseURL = "https://api.github.com"

// githubReleaseLister lists releases via the GitHub REST API, paginating fully.
type githubReleaseLister struct {
	org, repo, token string
	baseURL          string
	client           *http.Client
}

// NewGitHubReleaseSource returns a ReleaseSource backed by the GitHub REST API for
// org/repo. token, if non-empty, is sent as a bearer token to raise rate limits.
func NewGitHubReleaseSource(org, repo, token string) ReleaseSource {
	return &githubReleaseLister{
		org:     org,
		repo:    repo,
		token:   token,
		baseURL: defaultGitHubBaseURL,
		client:  &http.Client{Timeout: 10 * time.Minute}, // release downloads are tens of MB
	}
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
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

// FindRelease fetches the release for tag, including its assets, via the
// release-by-tag endpoint. The asset download URL comes from the API rather than
// being constructed, since asset filenames don't follow the tag exactly (the tag's
// leading v is dropped, e.g. tag v1.6.17 -> ziti-linux-amd64-1.6.17.tar.gz).
func (g *githubReleaseLister) FindRelease(ctx context.Context, tag string) (*ReleaseDetail, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", g.baseURL, g.org, g.repo, tag)
	resp, err := g.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching release %s: %w", tag, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("fetching release %s: unexpected status %s: %s", tag, resp.Status, body)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding release %s: %w", tag, err)
	}
	detail := &ReleaseDetail{Tag: rel.TagName}
	for _, a := range rel.Assets {
		detail.Assets = append(detail.Assets, Asset{Name: a.Name, DownloadURL: a.BrowserDownloadURL})
	}
	return detail, nil
}

// Download streams the asset at url to dst.
func (g *githubReleaseLister) Download(ctx context.Context, url string, dst io.Writer) error {
	resp, err := g.get(ctx, url)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: unexpected status %s", url, resp.Status)
	}
	if _, err := io.Copy(dst, resp.Body); err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	return nil
}

// get issues an authenticated GET with the client's standard headers.
func (g *githubReleaseLister) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	return g.client.Do(req)
}

func (g *githubReleaseLister) listPage(ctx context.Context, page int) ([]ghRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100&page=%d", g.baseURL, g.org, g.repo, page)
	resp, err := g.get(ctx, url)
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
