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
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCachedBinaryPathIncludesPlatform pins that cache entries name the platform
// they were produced for, so one id can be cached for several platforms at once.
func TestCachedBinaryPathIncludesPlatform(t *testing.T) {
	req := require.New(t)

	linux := cachedBinaryPath("/cache", "v2.0.8", platformName("linux", "amd64"))
	darwin := cachedBinaryPath("/cache", "v2.0.8", platformName("darwin", "arm64"))

	req.NotEqual(linux, darwin)
	req.Contains(linux, "ziti-v2.0.8-linux-amd64")
	req.Contains(darwin, "ziti-v2.0.8-darwin-arm64")
}

// TestAcquireCacheIsPerPlatform pins the reason the platform belongs in the cache
// key: a binary cached for one platform must never satisfy a request for another,
// which before would have handed a caller a binary it cannot execute. The cache
// hit takes no API call, so the erroring source proves the miss.
func TestAcquireCacheIsPerPlatform(t *testing.T) {
	req := require.New(t)
	cacheDir := t.TempDir()
	ctx := context.Background()
	cfg := testCfg()

	req.NoError(os.WriteFile(cachedBinaryPath(cacheDir, "v2.0.7", platformName("linux", "amd64")),
		[]byte(fakeBinaryContent), 0o755))

	// the platform it was cached for: hit, no API call
	path, _, err := acquireFor(ctx, "v2.0.7", cfg, erroringSource{}, cacheDir, WithPlatform("linux", "amd64"))
	req.NoError(err)
	req.Equal(cachedBinaryPath(cacheDir, "v2.0.7", platformName("linux", "amd64")), path)

	// any other platform: miss, so it goes to the API rather than serving the linux binary
	_, _, err = acquireFor(ctx, "v2.0.7", cfg, erroringSource{}, cacheDir, WithPlatform("darwin", "arm64"))
	req.ErrorContains(err, "unexpected API call")
}

// TestAcquireSelectsAssetForRequestedPlatform pins that WithPlatform reaches asset
// selection, so a release is downloaded for the platform asked for rather than the
// one doing the asking.
func TestAcquireSelectsAssetForRequestedPlatform(t *testing.T) {
	req := require.New(t)
	rs := newReleaseServer(t)
	ctx := context.Background()
	cfg := testCfg()

	// the fixture publishes a linux/amd64 asset
	path, id, err := acquireFor(ctx, "v2.0.8", cfg, rs.source(), t.TempDir(), WithPlatform("linux", "amd64"))
	req.NoError(err)
	req.Equal("v2.0.8", id.Tag)
	content, err := os.ReadFile(path)
	req.NoError(err)
	req.Equal(fakeBinaryContent, string(content))

	// and none for darwin/arm64, so asking for that platform must fail rather than
	// quietly fetching the linux one
	_, _, err = acquireFor(ctx, "v2.0.8", cfg, rs.source(), t.TempDir(), WithPlatform("darwin", "arm64"))
	req.ErrorContains(err, "no asset found")
	req.ErrorContains(err, "darwin")
}

// TestZitiMemoizedIsPerPlatform pins that the in-process memo distinguishes
// platforms, so a memoized result is not replayed for a platform it was not
// acquired for.
func TestZitiMemoizedIsPerPlatform(t *testing.T) {
	req := require.New(t)
	t.Cleanup(resetAcquireMemo)
	resetAcquireMemo()

	rs := newReleaseServer(t)
	cacheDir := t.TempDir()
	ctx := context.Background()
	cfg := testCfg()

	_, id, err := ZitiMemoized(ctx, "latest", cfg, rs.source(), cacheDir, WithPlatform("linux", "amd64"))
	req.NoError(err)
	req.Equal("v2.0.8", id.Tag)

	// same selector, different platform: no memo hit, so it resolves again
	_, _, err = ZitiMemoized(ctx, "latest", cfg, erroringSource{}, cacheDir, WithPlatform("darwin", "arm64"))
	req.ErrorContains(err, "unexpected API call")
}

// TestGoBuildEnv pins what the go commands are told. The target is always explicit,
// including for a native build: leaving it ambient would let an exported GOOS decide
// what gets built while the result is cached under the platform that was asked for.
// Only cgo differs, staying ambient natively and off when cross-building.
func TestGoBuildEnv(t *testing.T) {
	req := require.New(t)

	native := goBuildEnv(runtime.GOOS, runtime.GOARCH)
	req.True(slices.Contains(native, "GOOS="+runtime.GOOS), "native build must still pin GOOS")
	req.True(slices.Contains(native, "GOARCH="+runtime.GOARCH), "native build must still pin GOARCH")
	req.False(slices.Contains(native, "CGO_ENABLED=0"), "native build must leave cgo alone")

	crossGoarch := "arm64"
	if runtime.GOARCH == crossGoarch {
		crossGoarch = "amd64"
	}
	cross := goBuildEnv("linux", crossGoarch)
	req.True(slices.Contains(cross, "GOOS=linux"))
	req.True(slices.Contains(cross, "GOARCH="+crossGoarch))
	req.True(slices.Contains(cross, "CGO_ENABLED=0"))
}

// TestGoBuildEnvOverridesAmbientTarget pins that an exported GOOS/GOARCH cannot
// steer the build away from the platform that was asked for. The target is appended
// last, and the last assignment of a variable is the one the child process sees.
func TestGoBuildEnvOverridesAmbientTarget(t *testing.T) {
	req := require.New(t)

	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "386")

	env := goBuildEnv("linux", "amd64")

	req.Equal("GOOS=linux", lastAssignment(env, "GOOS"))
	req.Equal("GOARCH=amd64", lastAssignment(env, "GOARCH"))
}

// lastAssignment returns the final entry setting name, which is the one that wins.
func lastAssignment(env []string, name string) string {
	found := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, name+"=") {
			found = kv
		}
	}
	return found
}

// TestSelectAssetMatchesWholeTokens pins that a platform name must match a whole
// token of the asset name. Under a substring test a partial name passed for a real
// one, so "lin"/"md64" selected the linux/amd64 asset and it was cached under a
// platform nothing was built for. Structural validation cannot catch this: those are
// perfectly well-formed values, they are just not platforms.
func TestSelectAssetMatchesWholeTokens(t *testing.T) {
	assets := []Asset{
		{Name: "ziti-windows-amd64-2.0.8.zip"},
		{Name: "ziti-linux-x86_64-2.0.8.tar.gz"},
		{Name: "ziti-darwin-arm64-2.0.8.tar.gz"},
	}

	for _, tc := range []struct{ name, goos, goarch string }{
		{"truncated goos", "lin", "amd64"},
		{"truncated goarch", "linux", "md64"},
		{"both truncated", "lin", "md64"},
		{"goarch digits only", "linux", "64"},
		{"goos superstring", "linuxx", "amd64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := selectAsset(assets, tc.goos, tc.goarch)
			require.ErrorContains(t, err, "no asset found")
		})
	}

	// the real platform still resolves, including via an arch alias spelled with an
	// underscore, which must stay one token rather than splitting into x86 and 64
	a, err := selectAsset(assets, "linux", "amd64")
	require.NoError(t, err)
	require.Equal(t, "ziti-linux-x86_64-2.0.8.tar.gz", a.Name)
}

// TestSelectAssetRequiresAdjacentPlatformTokens pins that the os and arch must sit
// together in that order, as they do in the "<goos>-<arch>" segment of an asset name.
// Checked independently, an arch matches any token anywhere, so a version ending in
// the arch name is enough for a bogus platform to select a real asset.
func TestSelectAssetRequiresAdjacentPlatformTokens(t *testing.T) {
	// a version whose last component collides with an architecture name
	assets := []Asset{{Name: "ziti-linux-amd64-2.0.64.tar.gz"}}

	_, err := selectAsset(assets, "linux", "64")
	require.ErrorContains(t, err, "no asset found",
		"the version's trailing 64 must not stand in for the architecture")

	// reversed order is not a match either
	_, err = selectAsset([]Asset{{Name: "ziti-amd64-linux-2.0.8.tar.gz"}}, "linux", "amd64")
	require.ErrorContains(t, err, "no asset found")

	// the genuine pairing in the same name still resolves
	a, err := selectAsset(assets, "linux", "amd64")
	require.NoError(t, err)
	require.Equal(t, "ziti-linux-amd64-2.0.64.tar.gz", a.Name)
}

// TestAcquireRejectsUnusablePlatform pins that a platform that cannot describe a
// real binary is refused up front. Asset selection is a substring match, so an empty
// value matches every asset and would otherwise download an arbitrary one and cache
// it under a nameless platform. A path-bearing value would escape the cache dir.
func TestAcquireRejectsUnusablePlatform(t *testing.T) {
	req := require.New(t)
	rs := newReleaseServer(t)
	ctx := context.Background()
	cfg := testCfg()

	for _, tc := range []struct {
		name, goos, goarch, wants string
	}{
		{"empty goos", "", "amd64", "GOOS must not be empty"},
		{"empty goarch", "linux", "", "GOARCH must not be empty"},
		{"both empty", "", "", "GOOS must not be empty"},
		{"goos traversal", "../..", "amd64", "must not name a path"},
		{"goarch traversal", "linux", "..", "must not name a path"},
		{"goarch separator", "linux", "amd64/x", "must not name a path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := acquireFor(ctx, "v2.0.8", cfg, rs.source(), t.TempDir(),
				WithPlatform(tc.goos, tc.goarch))
			require.ErrorContains(t, err, tc.wants)
		})
	}

	// nothing was downloaded or cached on the way to those errors
	req.Zero(rs.downloads.Load())
}
