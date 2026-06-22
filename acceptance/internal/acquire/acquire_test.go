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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const fakeBinaryContent = "#!/bin/sh\necho fake ziti\n"

// makeTarGz builds a tar.gz containing the named entries.
func makeTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// releaseServer fakes the GitHub list, release-by-tag, and asset-download
// endpoints, counting downloads so cache behavior can be asserted.
type releaseServer struct {
	srv       *httptest.Server
	tarball   []byte
	downloads atomic.Int32
}

func newReleaseServer(t *testing.T) *releaseServer {
	t.Helper()
	rs := &releaseServer{tarball: makeTarGz(t, map[string]string{"ziti": fakeBinaryContent})}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/openziti/ziti/releases", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			writeJSON(t, w, []ghRelease{})
			return
		}
		writeJSON(t, w, []ghRelease{{TagName: "v1.6.17"}, {TagName: "v2.0.8"}})
	})
	mux.HandleFunc("/repos/openziti/ziti/releases/tags/v2.0.8", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, ghRelease{TagName: "v2.0.8", Assets: []ghAsset{
			{Name: "ziti-windows-amd64-2.0.8.zip", BrowserDownloadURL: rs.srv.URL + "/dl/win.zip"},
			// asset name drops the tag's leading v, as real releases do
			{Name: "ziti-linux-amd64-2.0.8.tar.gz", BrowserDownloadURL: rs.srv.URL + "/dl/ziti.tar.gz"},
		}})
	})
	mux.HandleFunc("/dl/ziti.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		rs.downloads.Add(1)
		_, _ = w.Write(rs.tarball)
	})
	rs.srv = httptest.NewServer(mux)
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *releaseServer) source() ReleaseSource {
	return &githubReleaseLister{
		org: "openziti", repo: "ziti",
		baseURL: rs.srv.URL,
		client:  rs.srv.Client(),
	}
}

func TestAcquireDownloadsExtractsAndCaches(t *testing.T) {
	rs := newReleaseServer(t)
	cacheDir := t.TempDir()
	ctx := context.Background()
	cfg := testCfg()

	// latest -> v2.0.8 -> download, extract, install
	path, id, err := acquireFor(ctx, "latest", cfg, rs.source(), cacheDir, "linux", "amd64")
	require.NoError(t, err)
	require.Equal(t, "v2.0.8", id.Tag)
	require.Equal(t, cachedBinaryPath(cacheDir, "v2.0.8"), path)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, fakeBinaryContent, string(content))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&0o111, "binary must be executable")
	require.Equal(t, int32(1), rs.downloads.Load())

	// no temp litter left behind
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// second acquire hits the cache: same path, no new download
	path2, _, err := acquireFor(ctx, "latest", cfg, rs.source(), cacheDir, "linux", "amd64")
	require.NoError(t, err)
	require.Equal(t, path, path2)
	require.Equal(t, int32(1), rs.downloads.Load(), "cache hit must not re-download")
}

// TestAcquireGitRefShaCached pins the source-build cache path without touching
// the network: a full SHA passes through resolution unchanged, so a cached
// binary for it is returned with zero git or API calls.
func TestAcquireGitRefShaCached(t *testing.T) {
	req := require.New(t)
	cacheDir := t.TempDir()
	sha := "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"
	req.NoError(os.WriteFile(cachedBinaryPath(cacheDir, sha), []byte(fakeBinaryContent), 0o755))

	path, id, err := acquireFor(context.Background(), sha, testCfg(), erroringSource{}, cacheDir, "linux", "amd64")
	req.NoError(err)
	req.True(id.SourceBuilt)
	req.Equal(sha, id.Tag)
	req.Equal(cachedBinaryPath(cacheDir, sha), path)
}

// erroringSource fails every API operation, proving a code path makes no API
// calls at all.
type erroringSource struct{}

func (erroringSource) List(context.Context) ([]Release, error) {
	return nil, errors.New("unexpected API call: List")
}
func (erroringSource) FindRelease(context.Context, string) (*ReleaseDetail, error) {
	return nil, errors.New("unexpected API call: FindRelease")
}
func (erroringSource) Download(context.Context, string, io.Writer) error {
	return errors.New("unexpected API call: Download")
}

// TestAcquirePinnedCachedSkipsAPI pins the rate-limit shortcut: a selector that
// pins a concrete tag (an explicit version, or a label with a non-wildcard value)
// must make zero API calls when the binary is already cached. Moving selectors
// must still resolve.
func TestAcquirePinnedCachedSkipsAPI(t *testing.T) {
	req := require.New(t)
	cfg := testCfg()
	cacheDir := t.TempDir()
	ctx := context.Background()

	// pre-place cached binaries for the pinned tags
	for _, tag := range []string{"v1.6.17", "v2.0.7"} {
		req.NoError(os.WriteFile(cachedBinaryPath(cacheDir, tag), []byte(fakeBinaryContent), 0o755))
	}

	// explicit version: cache hit, no API
	path, id, err := acquireFor(ctx, "v2.0.7", cfg, erroringSource{}, cacheDir, "linux", "amd64")
	req.NoError(err)
	req.Equal("v2.0.7", id.Tag)
	req.Equal(cachedBinaryPath(cacheDir, "v2.0.7"), path)

	// pinned label (maint-lts -> v1.6.17): cache hit, no API
	path, id, err = acquireFor(ctx, "maint-lts", cfg, erroringSource{}, cacheDir, "linux", "amd64")
	req.NoError(err)
	req.Equal("v1.6.17", id.Tag)
	req.Equal(cachedBinaryPath(cacheDir, "v1.6.17"), path)

	// moving selectors must still resolve, even with a full cache
	_, _, err = acquireFor(ctx, "latest", cfg, erroringSource{}, cacheDir, "linux", "amd64")
	req.ErrorContains(err, "unexpected API call")
	_, _, err = acquireFor(ctx, "active-lts", cfg, erroringSource{}, cacheDir, "linux", "amd64") // v2.0.x wildcard
	req.ErrorContains(err, "unexpected API call")

	// a pinned tag with a cold cache must verify via the API
	_, _, err = acquireFor(ctx, "v9.9.9", cfg, erroringSource{}, cacheDir, "linux", "amd64")
	req.ErrorContains(err, "unexpected API call")
}

// TestZitiMemoized pins the process-wide memo: the second acquisition for a
// selector must not touch the API, and failures must not be cached.
func TestZitiMemoized(t *testing.T) {
	req := require.New(t)
	t.Cleanup(resetAcquireMemo)
	resetAcquireMemo()

	rs := newReleaseServer(t)
	cacheDir := t.TempDir()
	ctx := context.Background()
	cfg := testCfg()

	// a failure is not cached: a later call retries
	_, _, err := ZitiMemoized(ctx, "latest", cfg, erroringSource{}, cacheDir)
	req.Error(err)

	path, id, err := ZitiMemoized(ctx, "latest", cfg, rs.source(), cacheDir)
	req.NoError(err)
	req.Equal("v2.0.8", id.Tag)

	// second call: memo hit, zero API calls even with an erroring source
	path2, id2, err := ZitiMemoized(ctx, "latest", cfg, erroringSource{}, cacheDir)
	req.NoError(err)
	req.Equal(path, path2)
	req.Equal(id, id2)
}

// TestRateLimitErrorIsDirected pins the 403 hint: a rate-limited response must
// produce an error that names GITHUB_TOKEN as the fix.
func TestRateLimitErrorIsDirected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded for 1.2.3.4."}`))
	}))
	t.Cleanup(srv.Close)
	_, err := githubListerFor(srv).List(context.Background())
	require.ErrorContains(t, err, "set GITHUB_TOKEN")
}

func TestSelectAsset(t *testing.T) {
	assets := []Asset{
		{Name: "ziti-windows-amd64-2.0.8.zip"},
		{Name: "ziti-linux-x86_64-2.0.8.tar.gz"}, // older releases use x86_64
		{Name: "ziti-darwin-arm64-2.0.8.tar.gz"},
	}

	a, err := selectAsset(assets, "linux", "amd64")
	require.NoError(t, err)
	require.Equal(t, "ziti-linux-x86_64-2.0.8.tar.gz", a.Name)

	a, err = selectAsset(assets, "darwin", "arm64")
	require.NoError(t, err)
	require.Equal(t, "ziti-darwin-arm64-2.0.8.tar.gz", a.Name)

	_, err = selectAsset(assets, "windows", "amd64")
	require.ErrorContains(t, err, "zip extraction not supported")

	_, err = selectAsset(assets, "linux", "riscv64")
	require.ErrorContains(t, err, "no asset found")
}

func TestExtractZitiBinaryNested(t *testing.T) {
	// binary nested in a directory, alongside a decoy whose base name isn't ziti
	tarball := makeTarGz(t, map[string]string{
		"release/notes.txt": "hi",
		"release/ziti":      fakeBinaryContent,
	})
	dst := t.TempDir() + "/ziti"
	require.NoError(t, extractZitiBinary(bytes.NewReader(tarball), dst))
	content, err := os.ReadFile(dst)
	require.NoError(t, err)
	require.Equal(t, fakeBinaryContent, string(content))
}

func TestExtractZitiBinaryMissing(t *testing.T) {
	tarball := makeTarGz(t, map[string]string{"readme.md": "no binary here"})
	err := extractZitiBinary(bytes.NewReader(tarball), t.TempDir()+"/ziti")
	require.ErrorContains(t, err, "does not contain a ziti binary")
}
