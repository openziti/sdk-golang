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
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// Option customizes how a binary is acquired.
type Option func(*buildOptions)

// buildOptions holds the resolved acquire options.
type buildOptions struct {
	stampVersion string
	goos         string
	goarch       string
}

// newBuildOptions applies opts and returns the resolved options, defaulting the
// target platform to the one this process runs on.
func newBuildOptions(opts []Option) buildOptions {
	bo := buildOptions{
		goos:   runtime.GOOS,
		goarch: runtime.GOARCH,
	}
	for _, opt := range opts {
		opt(&bo)
	}
	return bo
}

// platform is the target platform as it appears in cache entry names.
func (bo buildOptions) platform() string {
	return platformName(bo.goos, bo.goarch)
}

// validate rejects a target platform that cannot describe a real binary. It is a
// structural check, not a list of known platforms: an empty value matches every
// release asset, since asset selection is a substring match, and would otherwise
// download an arbitrary one and cache it under a nameless platform. A value
// carrying a path separator would escape the cache directory.
func (bo buildOptions) validate() error {
	if err := validPlatformPart("GOOS", bo.goos); err != nil {
		return err
	}
	return validPlatformPart("GOARCH", bo.goarch)
}

// validPlatformPart checks one half of a target platform.
func validPlatformPart(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%s %q must not name a path", name, value)
	}
	return nil
}

// WithVersion stamps the built binary's common/version Version (and Revision) when a git-ref
// selector is built from source, so it reports version rather than the unstamped dev default
// ("v0.0.0"). Binaries built from the same commit but stamped with different versions cache
// separately. It has no effect on release selectors, whose artifacts are already stamped.
func WithVersion(version string) Option {
	return func(o *buildOptions) { o.stampVersion = version }
}

// WithPlatform targets goos/goarch instead of the platform this process runs on.
// Release selectors then download that platform's asset, and git-ref selectors
// cross-build for it. Use it when the binary runs somewhere other than the
// machine acquiring it, for example a test harness on a mac provisioning
// linux/amd64 hosts. Cache entries record the platform they were produced for, so
// the same commit acquired for two platforms caches separately.
func WithPlatform(goos, goarch string) Option {
	return func(o *buildOptions) {
		o.goos = goos
		o.goarch = goarch
	}
}

// Ziti resolves selector to an immutable id and returns the path to a ziti
// binary for it: release selectors download the release artifact on a cache
// miss, and git-ref selectors (a branch, non-release tag, or SHA) resolve to a
// commit and build from source. The cache is keyed on the immutable id (tag or
// SHA) and the target platform, so a moved mutable selector misses the cache
// rather than serving a stale binary, and a binary is never served to a platform
// it was not produced for.
//
// The binary targets this process's platform unless WithPlatform selects another.
func Ziti(ctx context.Context, selector string, cfg Versions, src ReleaseSource, cacheDir string, opts ...Option) (string, ResolvedID, error) {
	return acquireFor(ctx, selector, cfg, src, cacheDir, opts...)
}

// acquireMemo caches successful Ziti results per selector for the life of the
// process, so a test suite whose tests each start a harness resolves each
// selector once instead of re-querying the GitHub API per test. Failures are not
// cached, so a transient error doesn't poison the process.
var acquireMemo = struct {
	sync.Mutex
	bySelector map[string]memoEntry
}{bySelector: map[string]memoEntry{}}

type memoEntry struct {
	binPath string
	id      ResolvedID
}

// resetAcquireMemo clears the process-wide memo; for tests.
func resetAcquireMemo() {
	acquireMemo.Lock()
	defer acquireMemo.Unlock()
	acquireMemo.bySelector = map[string]memoEntry{}
}

// ZitiMemoized is Ziti with a process-wide, per-selector memo of successful
// results. Within one process a moving selector (latest, a wildcard label) thus
// resolves once, which also keeps every test in a suite on the same version. The
// lock is held across a cache-miss download, so concurrent callers can't
// duplicate work.
func ZitiMemoized(ctx context.Context, selector string, cfg Versions, src ReleaseSource, cacheDir string, opts ...Option) (string, ResolvedID, error) {
	acquireMemo.Lock()
	defer acquireMemo.Unlock()

	// A stamped version and a target platform each produce a distinct binary, so both must key the
	// memo separately from a plain acquire of the same selector.
	bo := newBuildOptions(opts)
	memoKey := selector + "\x00" + bo.platform()
	if bo.stampVersion != "" {
		memoKey += "\x00" + bo.stampVersion
	}

	if entry, ok := acquireMemo.bySelector[memoKey]; ok {
		return entry.binPath, entry.id, nil
	}
	binPath, id, err := Ziti(ctx, selector, cfg, src, cacheDir, opts...)
	if err != nil {
		return "", ResolvedID{}, err
	}
	acquireMemo.bySelector[memoKey] = memoEntry{binPath: binPath, id: id}
	return binPath, id, nil
}

// acquireFor is Ziti with the options already resolved, including the target
// platform, which defaults to this process's but may be pinned via WithPlatform.
func acquireFor(ctx context.Context, selector string, cfg Versions, src ReleaseSource, cacheDir string, opts ...Option) (string, ResolvedID, error) {
	bo := newBuildOptions(opts)
	// Validate before any cache lookup or asset selection, both of which would otherwise accept a
	// meaningless platform and produce a binary that cannot be attributed to one.
	if err := bo.validate(); err != nil {
		return "", ResolvedID{}, err
	}

	spec, err := ParseSpec(selector, cfg)
	if err != nil {
		return "", ResolvedID{}, err
	}

	// Git refs resolve to a commit and build from source.
	if spec.Kind == SpecGitRef {
		sha, err := resolveRefToSha(ctx, cfg.Source, spec.Raw)
		if err != nil {
			return "", ResolvedID{}, err
		}
		id := ResolvedID{Tag: sha, SourceBuilt: true}

		// In co-development mode the binary embeds the local SDK tree, so the
		// cache key must identify both sides; a dirty SDK tree has no immutable
		// id, so it always rebuilds.
		cacheKey := sha
		sdkReplace := ""
		useCache := true
		if buildWithLocalSdk() {
			sdkRoot, err := localSdkRoot()
			if err != nil {
				return "", ResolvedID{}, err
			}
			sdkReplace = sdkRoot
			head, dirty, err := localSdkFingerprint(ctx, sdkRoot)
			if err != nil {
				return "", ResolvedID{}, err
			}
			cacheKey = sha + "-sdk-" + head[:12]
			useCache = !dirty
		}

		// A stamped version changes the binary, so it must key the cache separately from an
		// unstamped build of the same commit.
		if bo.stampVersion != "" {
			cacheKey += versionCacheSuffix(bo.stampVersion)
		}

		if useCache {
			binPath := cachedBinaryPath(cacheDir, cacheKey, bo.platform())
			if _, statErr := os.Stat(binPath); statErr == nil {
				return binPath, id, nil
			}
		}
		path, err := buildZitiFromSource(ctx, cfg.Source, sha, cacheDir, cacheKey, sdkReplace, bo.stampVersion, bo.goos, bo.goarch)
		if err != nil {
			return "", ResolvedID{}, err
		}
		return path, id, nil
	}

	// A selector that pins a concrete tag needs no API round trip when the
	// binary is already cached: the cache entry is proof the release exists.
	// Moving selectors (latest, wildcards) must still resolve.
	if tag, pinned := pinnedTag(spec, cfg); pinned {
		binPath := cachedBinaryPath(cacheDir, tag, bo.platform())
		if _, statErr := os.Stat(binPath); statErr == nil {
			return binPath, ResolvedID{Tag: tag}, nil
		}
	}

	id, err := ResolveTag(ctx, spec, cfg, src)
	if err != nil {
		return "", ResolvedID{}, err
	}

	binPath := cachedBinaryPath(cacheDir, id.Tag, bo.platform())
	if _, statErr := os.Stat(binPath); statErr == nil {
		return binPath, id, nil
	}

	detail, err := src.FindRelease(ctx, id.Tag)
	if err != nil {
		return "", ResolvedID{}, err
	}
	asset, err := selectAsset(detail.Assets, bo.goos, bo.goarch)
	if err != nil {
		return "", ResolvedID{}, fmt.Errorf("release %s: %w", id.Tag, err)
	}

	path, err := downloadAndInstall(ctx, src, asset, cacheDir, id.Tag, bo.platform())
	if err != nil {
		return "", ResolvedID{}, err
	}
	return path, id, nil
}

// pinnedTag returns the concrete release tag a spec pins, if any: an explicit
// release version, or a label whose versions.yaml value is a concrete tag rather
// than a vM.m.x wildcard. The built-in latest label never pins.
func pinnedTag(spec Spec, cfg Versions) (string, bool) {
	switch spec.Kind {
	case SpecReleaseVersion:
		return spec.Raw, true
	case SpecLabel:
		if spec.Label == LabelLatest {
			return "", false
		}
		val := cfg.Labels[spec.Label]
		if val == "" || strings.HasSuffix(val, ".x") {
			return "", false
		}
		return val, true
	default:
		return "", false
	}
}

// downloadAndInstall downloads asset, extracts the ziti binary, and installs it
// into the cache. All temp files live in the cache dir so the final rename is
// same-filesystem and atomic.
func downloadAndInstall(ctx context.Context, src ReleaseSource, asset Asset, cacheDir, id, platform string) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}

	archive, err := os.CreateTemp(cacheDir, "download-*")
	if err != nil {
		return "", fmt.Errorf("creating download temp file: %w", err)
	}
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archive.Name())
	}()

	if err := src.Download(ctx, asset.DownloadURL, archive); err != nil {
		return "", err
	}
	if _, err := archive.Seek(0, 0); err != nil {
		return "", fmt.Errorf("rewinding archive: %w", err)
	}

	extracted, err := os.CreateTemp(cacheDir, "extract-*")
	if err != nil {
		return "", fmt.Errorf("creating extract temp file: %w", err)
	}
	extractedName := extracted.Name()
	_ = extracted.Close()
	defer func() { _ = os.Remove(extractedName) }()

	if err := extractZitiBinary(archive, extractedName); err != nil {
		return "", fmt.Errorf("extracting %s: %w", asset.Name, err)
	}
	return installIntoCache(cacheDir, id, platform, extractedName)
}

// archAliases maps a GOARCH to the names release assets use for it.
var archAliases = map[string][]string{
	"amd64": {"amd64", "x86_64"},
	"arm64": {"arm64", "aarch64"},
}

// assetNameTokens splits an asset name into the tokens platform matching compares
// against: runs of letters, digits and underscores, so "ziti-linux-x86_64-2.0.8.tar.gz"
// yields "linux" and "x86_64" among others. The underscore stays inside a token
// because arch names such as x86_64 contain one.
func assetNameTokens(name string) []string {
	return strings.FieldsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_'
	})
}

// matchesPlatform reports whether tokens name goos immediately followed by one of
// arches, as the "<goos>-<arch>" segment of a release asset name does.
//
// Both halves must be whole tokens, and they must be adjacent in that order. Whole
// tokens stop a partial name passing for a real one, where "lin"/"md64" would select
// the linux/amd64 asset. Adjacency ties the two halves to the same segment: tested
// independently, an arch could match an unrelated token elsewhere in the name, so
// "linux"/"64" would match ziti-linux-amd64-2.0.64.tar.gz through its version. Either
// way the binary would be cached under a platform nothing was built for, instead of
// reaching the "no asset found" error an unknown platform should get.
func matchesPlatform(tokens []string, goos string, arches []string) bool {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == goos && slices.Contains(arches, tokens[i+1]) {
			return true
		}
	}
	return false
}

// selectAsset picks the release asset for goos/goarch. Only tar.gz archives are
// supported; a release whose only platform match is a zip is reported distinctly so
// the gap is obvious if the harness ever runs somewhere zip-packaged.
func selectAsset(assets []Asset, goos, goarch string) (Asset, error) {
	arches := archAliases[goarch]
	if arches == nil {
		arches = []string{goarch}
	}

	var zipMatch string
	for _, a := range assets {
		name := strings.ToLower(a.Name)
		if !matchesPlatform(assetNameTokens(name), goos, arches) {
			continue
		}
		if strings.HasSuffix(name, ".tar.gz") {
			return a, nil
		}
		if strings.HasSuffix(name, ".zip") {
			zipMatch = a.Name
		}
	}
	if zipMatch != "" {
		return Asset{}, fmt.Errorf("no tar.gz asset for %s/%s (found zip %q; zip extraction not supported)", goos, goarch, zipMatch)
	}
	return Asset{}, fmt.Errorf("no asset found for %s/%s", goos, goarch)
}
