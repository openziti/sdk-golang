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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// BuildWithLocalSdkEnv when "true", makes source builds replace the ziti ref's
// pinned sdk-golang with the local SDK tree (the code under test). This is the
// co-development mode: a ziti branch developed in lockstep with an SDK branch
// (e.g. connect-v2) doesn't build purely until its go.mod pins a pushed SDK
// version, and the binary the tests talk to should embed the same SDK lineage
// they're testing. Cache keys include the local SDK's commit; a dirty SDK tree
// bypasses the cache entirely so iteration never serves a stale binary.
const BuildWithLocalSdkEnv = "ZITI_ACCEPTANCE_BUILD_WITH_LOCAL_SDK"

// buildWithLocalSdk reports whether co-development mode is enabled.
func buildWithLocalSdk() bool {
	return os.Getenv(BuildWithLocalSdkEnv) == "true"
}

// localSdkRoot locates the SDK tree under test: the parent of the acceptance
// module root (found via versions.yaml).
func localSdkRoot() (string, error) {
	cfgPath, err := FindVersionsFile()
	if err != nil {
		return "", err
	}
	return filepath.Dir(filepath.Dir(cfgPath)), nil
}

// localSdkFingerprint identifies the local SDK tree's state for cache keying:
// its HEAD commit, and whether the tree is dirty (in which case caching must be
// bypassed, since the content isn't identified by any immutable id).
func localSdkFingerprint(ctx context.Context, sdkRoot string) (head string, dirty bool, err error) {
	out, err := runCmd(ctx, sdkRoot, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", false, fmt.Errorf("fingerprinting local sdk: %w", err)
	}
	head = strings.TrimSpace(out)

	status, err := runCmd(ctx, sdkRoot, "git", "status", "--porcelain")
	if err != nil {
		return "", false, fmt.Errorf("fingerprinting local sdk: %w", err)
	}
	return head, strings.TrimSpace(status) != "", nil
}

var fullShaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// resolveRefToSha resolves a git ref (branch or tag) on the source repository to
// its full commit SHA via git ls-remote, so mutable refs become immutable ids
// before any cache interaction. A full SHA passes through unchanged.
func resolveRefToSha(ctx context.Context, src Source, ref string) (string, error) {
	if fullShaRe.MatchString(ref) {
		return ref, nil
	}

	out, err := runCmd(ctx, "", "git", "ls-remote", gitURL(src), ref, ref+"^{}")
	if err != nil {
		return "", fmt.Errorf("resolving ref %q: %w", ref, err)
	}

	// for an annotated tag prefer the peeled (^{}) commit; otherwise the first hit
	var sha string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if sha == "" || strings.HasSuffix(fields[1], "^{}") {
			sha = fields[0]
		}
	}
	if sha == "" {
		return "", fmt.Errorf("ref %q not found on %s", ref, gitURL(src))
	}
	return sha, nil
}

// buildZitiFromSource shallow-fetches the source repository at exactly sha (so a
// branch moving between resolution and fetch cannot change what's built), builds
// the ziti binary, and installs it into the cache under cacheKey. In
// co-development mode (sdkReplace non-empty) the ref's pinned sdk-golang is
// replaced with that local tree before building. The source checkout is
// temporary; Go's module cache keeps rebuilds reasonably fast.
func buildZitiFromSource(ctx context.Context, src Source, sha, cacheDir, cacheKey, sdkReplace string) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	srcDir, err := os.MkdirTemp(cacheDir, "src-"+sha[:12]+"-*")
	if err != nil {
		return "", fmt.Errorf("creating source temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(srcDir) }()

	steps := [][]string{
		{"git", "init", "--quiet"},
		{"git", "remote", "add", "origin", gitURL(src)},
		{"git", "fetch", "--quiet", "--depth=1", "origin", sha},
		{"git", "checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, step := range steps {
		if _, err := runCmd(ctx, srcDir, step[0], step[1:]...); err != nil {
			return "", fmt.Errorf("fetching source at %s: %w", sha[:12], err)
		}
	}

	if sdkReplace != "" {
		if _, err := runCmd(ctx, srcDir, "go", "mod", "edit",
			"-replace", "github.com/openziti/sdk-golang/v2="+sdkReplace); err != nil {
			return "", fmt.Errorf("replacing sdk-golang with local tree: %w", err)
		}
		if _, err := runCmd(ctx, srcDir, "go", "mod", "tidy"); err != nil {
			return "", fmt.Errorf("tidying after sdk replace: %w", err)
		}
	}

	builtPath := filepath.Join(cacheDir, "build-"+sha[:12]+".tmp")
	defer func() { _ = os.Remove(builtPath) }()
	if _, err := runCmd(ctx, srcDir, "go", "build", "-o", builtPath, "./ziti"); err != nil {
		err = fmt.Errorf("building ziti at %s: %w", sha[:12], err)
		if sdkReplace == "" {
			err = fmt.Errorf("%w\n(if this ref co-develops with the SDK, set %s=true to build it against the local SDK tree)",
				err, BuildWithLocalSdkEnv)
		}
		return "", err
	}

	return installIntoCache(cacheDir, cacheKey, builtPath)
}

// gitURL is the https clone URL for the source repository.
func gitURL(src Source) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", src.Org, src.Repo)
}

// runCmd runs a command, returning stdout and folding stderr into the error.
func runCmd(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w\nstderr: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
