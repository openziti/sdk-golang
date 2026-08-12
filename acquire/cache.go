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
	"fmt"
	"os"
	"path/filepath"
)

// CacheDirEnv overrides the binary cache location when set.
const CacheDirEnv = "ZITI_ACCEPTANCE_CACHE"

// DefaultCacheDir returns the binary cache directory: $ZITI_ACCEPTANCE_CACHE if
// set, else <user cache dir>/ziti-acceptance/bin.
func DefaultCacheDir() (string, error) {
	if dir := os.Getenv(CacheDirEnv); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating user cache dir: %w", err)
	}
	return filepath.Join(base, "ziti-acceptance", "bin"), nil
}

// platformName renders a target platform the way cache entries name it.
func platformName(goos, goarch string) string {
	return goos + "-" + goarch
}

// cachedBinaryPath is the cache location for the binary of an immutable id (a
// concrete release tag or a commit SHA) built for platform ("<goos>-<goarch>").
// The cache is keyed only on immutable ids, never on a mutable selector, so a
// moved selector misses rather than serving a stale binary. Every entry names the
// platform it was produced for, so a binary is never served to a platform it
// cannot run on.
func cachedBinaryPath(cacheDir, id, platform string) string {
	return filepath.Join(cacheDir, "ziti-"+id+"-"+platform)
}

// installIntoCache atomically installs the file at srcPath as the cached binary for
// id on platform: a rename within the cache directory, so a concurrent or
// interrupted run never observes a partial binary.
func installIntoCache(cacheDir, id, platform, srcPath string) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	dst := cachedBinaryPath(cacheDir, id, platform)
	if err := os.Rename(srcPath, dst); err != nil {
		return "", fmt.Errorf("installing into cache: %w", err)
	}
	return dst, nil
}
