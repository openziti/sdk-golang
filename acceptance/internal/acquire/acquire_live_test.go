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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAcquireLive downloads a real release from GitHub and runs it. Opt-in via
// ZITI_ACCEPTANCE_LIVE=1 so the regular suite stays network-free; its value is
// catching drift between our assumptions and the real release API/asset layout.
func TestAcquireLive(t *testing.T) {
	if os.Getenv("ZITI_ACCEPTANCE_LIVE") != "1" {
		t.Skip("set ZITI_ACCEPTANCE_LIVE=1 to run against the live GitHub API")
	}

	cfg, err := LoadVersions("../../versions.yaml")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	src := NewGitHubReleaseSource(cfg.Source.Org, cfg.Source.Repo, os.Getenv("GITHUB_TOKEN"))
	binPath, id, err := Acquire(ctx, "maint-lts", cfg, src, t.TempDir())
	require.NoError(t, err)
	require.Equal(t, cfg.Labels["maint-lts"], id.Tag)

	out, err := exec.CommandContext(ctx, binPath, "--version").CombinedOutput()
	require.NoError(t, err, "downloaded binary failed to run: %s", out)
	require.Contains(t, strings.TrimSpace(string(out)), strings.TrimPrefix(id.Tag, "v"))
}
