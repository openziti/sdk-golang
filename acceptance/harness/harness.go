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

// Package harness brings up real, versioned OpenZiti controllers and routers as
// local child processes so the SDK in this tree can be exercised against them. The
// version under test is selected by ZITI_ACCEPTANCE_VERSION (default "latest"): a
// label, a release version, or any git ref.
package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/openziti/sdk-golang/acceptance/internal/acquire"
	"github.com/openziti/sdk-golang/acceptance/internal/ziticli"
)

// VersionEnv selects the ziti version under test. Empty means "latest".
const VersionEnv = "ZITI_ACCEPTANCE_VERSION"

// Harness is a running acceptance environment: a controller, the default edge
// router, and any routers a test adds, all separate child processes, with admin
// access for setup.
type Harness struct {
	home          string
	version       Version
	cli           *ziticli.Cli
	ctrl          *controller
	defaultRouter *Router
}

// StartShared brings up the default topology (one controller, one edge router) for
// the whole test package, for use from TestMain. It is not bound to a *testing.T;
// the caller runs the returned teardown after m.Run().
func StartShared() (*Harness, func(), error) {
	selector := os.Getenv(VersionEnv)
	if selector == "" {
		selector = "latest"
	}

	cfgPath, err := acquire.FindVersionsFile()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := acquire.LoadVersions(cfgPath)
	if err != nil {
		return nil, nil, err
	}

	cacheDir, err := acquire.DefaultCacheDir()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	src := acquire.NewGitHubReleaseSource(cfg.Source.Org, cfg.Source.Repo, os.Getenv("GITHUB_TOKEN"))
	// memoized: a suite whose tests each start a harness resolves the selector
	// once per process, keeping every test on the same version and off the
	// GitHub API rate limit
	binPath, id, err := acquire.ZitiMemoized(ctx, selector, cfg, src, cacheDir)
	if err != nil {
		return nil, nil, fmt.Errorf("acquiring ziti for selector %q: %w", selector, err)
	}
	version := Version{tag: id.Tag, sourceBuilt: id.SourceBuilt}

	home, err := os.MkdirTemp("", "ziti-acceptance-*")
	if err != nil {
		return nil, nil, err
	}
	// CLI state lives inside home, so one teardown removes everything
	cli := ziticli.New(binPath, filepath.Join(home, "cli-config"))

	ctrl, err := startController(cli, home)
	if err != nil {
		_ = os.RemoveAll(home)
		return nil, nil, err
	}

	h := &Harness{home: home, version: version, cli: cli, ctrl: ctrl}
	teardown := func() {
		if h.defaultRouter != nil {
			h.defaultRouter.stopProcess()
		}
		ctrl.stop()
		_ = os.RemoveAll(home)
	}

	if err := ctrl.awaitAdminUsable(ctx, cli, version); err != nil {
		teardown()
		return nil, nil, err
	}

	// the default topology includes one edge router; tests that need more add
	// their own, and lifecycle tests bring up their own environment
	r, err := h.addRouter("edge1")
	if err != nil {
		teardown()
		return nil, nil, fmt.Errorf("starting default router: %w", err)
	}
	h.defaultRouter = r

	return h, teardown, nil
}

// DefaultRouter returns the environment's shared edge router. Tests must not
// stop or restart it; lifecycle tests use their own environment and routers.
func (h *Harness) DefaultRouter() *Router {
	return h.defaultRouter
}

// Start brings up an environment scoped to a single test, registering teardown
// with t. Use it for a test that wants its own environment rather than the
// package-shared one from StartShared; tests that stop or restart components must
// use their own environment.
func Start(t testing.TB) *Harness {
	t.Helper()
	h, teardown, err := StartShared()
	if err != nil {
		t.Fatalf("starting harness: %v", err)
	}
	t.Cleanup(teardown)
	return h
}

// Version returns the resolved version of the ziti under test.
func (h *Harness) Version() Version {
	return h.version
}

// RequireMinVersion skips the test unless the version under test is at least
// minVersion; source-built refs satisfy every minimum.
func (h *Harness) RequireMinVersion(t testing.TB, minVersion string) {
	t.Helper()
	if !h.version.AtLeast(minVersion) {
		t.Skipf("requires ziti >= %s, testing against %s", minVersion, h.version)
	}
}

// Cli runs a ziti CLI command against this harness with the admin login already in
// place, returning stdout and failing t on error.
func (h *Harness) Cli(t testing.TB, args ...string) string {
	t.Helper()
	out, err := h.cli.Run(context.Background(), args...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

// ControllerHostPort returns the host:port of the controller's edge API.
func (h *Harness) ControllerHostPort() string {
	return h.ctrl.hostPort
}

