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
	"strings"
	"sync"
)

// Ziti resolves selector to an immutable id and returns the path to a ziti
// binary for it: release selectors download the release artifact on a cache
// miss, and git-ref selectors (a branch, non-release tag, or SHA) resolve to a
// commit and build from source. The cache is keyed on the immutable id (tag or
// SHA), so a moved mutable selector misses the cache rather than serving a
// stale binary.
func Ziti(ctx context.Context, selector string, cfg Versions, src ReleaseSource, cacheDir string) (string, ResolvedID, error) {
	return acquireFor(ctx, selector, cfg, src, cacheDir, runtime.GOOS, runtime.GOARCH)
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
func ZitiMemoized(ctx context.Context, selector string, cfg Versions, src ReleaseSource, cacheDir string) (string, ResolvedID, error) {
	acquireMemo.Lock()
	defer acquireMemo.Unlock()

	if entry, ok := acquireMemo.bySelector[selector]; ok {
		return entry.binPath, entry.id, nil
	}
	binPath, id, err := Ziti(ctx, selector, cfg, src, cacheDir)
	if err != nil {
		return "", ResolvedID{}, err
	}
	acquireMemo.bySelector[selector] = memoEntry{binPath: binPath, id: id}
	return binPath, id, nil
}

// acquireFor is Ziti with the platform injected, so tests can pin it.
func acquireFor(ctx context.Context, selector string, cfg Versions, src ReleaseSource, cacheDir, goos, goarch string) (string, ResolvedID, error) {
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

		if useCache {
			binPath := cachedBinaryPath(cacheDir, cacheKey)
			if _, statErr := os.Stat(binPath); statErr == nil {
				return binPath, id, nil
			}
		}
		path, err := buildZitiFromSource(ctx, cfg.Source, sha, cacheDir, cacheKey, sdkReplace)
		if err != nil {
			return "", ResolvedID{}, err
		}
		return path, id, nil
	}

	// A selector that pins a concrete tag needs no API round trip when the
	// binary is already cached: the cache entry is proof the release exists.
	// Moving selectors (latest, wildcards) must still resolve.
	if tag, pinned := pinnedTag(spec, cfg); pinned {
		binPath := cachedBinaryPath(cacheDir, tag)
		if _, statErr := os.Stat(binPath); statErr == nil {
			return binPath, ResolvedID{Tag: tag}, nil
		}
	}

	id, err := ResolveTag(ctx, spec, cfg, src)
	if err != nil {
		return "", ResolvedID{}, err
	}

	binPath := cachedBinaryPath(cacheDir, id.Tag)
	if _, statErr := os.Stat(binPath); statErr == nil {
		return binPath, id, nil
	}

	detail, err := src.FindRelease(ctx, id.Tag)
	if err != nil {
		return "", ResolvedID{}, err
	}
	asset, err := selectAsset(detail.Assets, goos, goarch)
	if err != nil {
		return "", ResolvedID{}, fmt.Errorf("release %s: %w", id.Tag, err)
	}

	path, err := downloadAndInstall(ctx, src, asset, cacheDir, id.Tag)
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
func downloadAndInstall(ctx context.Context, src ReleaseSource, asset Asset, cacheDir, id string) (string, error) {
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
	return installIntoCache(cacheDir, id, extractedName)
}

// archAliases maps a GOARCH to the names release assets use for it.
var archAliases = map[string][]string{
	"amd64": {"amd64", "x86_64"},
	"arm64": {"arm64", "aarch64"},
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
		if !strings.Contains(name, goos) {
			continue
		}
		archMatch := false
		for _, arch := range arches {
			if strings.Contains(name, arch) {
				archMatch = true
				break
			}
		}
		if !archMatch {
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
