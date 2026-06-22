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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeVersions(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "versions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadVersions(t *testing.T) {
	path := writeVersions(t, `
labels:
  active-lts: v2.0.x
  maint-lts: v1.6.17
source:
  org: openziti
  repo: ziti
`)
	v, err := LoadVersions(path)
	require.NoError(t, err)
	require.Equal(t, "v2.0.x", v.Labels["active-lts"])
	require.Equal(t, "v1.6.17", v.Labels["maint-lts"])
	require.Equal(t, "openziti", v.Source.Org)
	require.Equal(t, "ziti", v.Source.Repo)
}

func TestLoadVersionsRejectsUnknownField(t *testing.T) {
	path := writeVersions(t, `
labels:
  active-lts: v2.0.x
source:
  org: openziti
  repo: ziti
nonsense: true
`)
	_, err := LoadVersions(path)
	require.Error(t, err)
}

func TestLoadVersionsRequiresSource(t *testing.T) {
	path := writeVersions(t, `
labels:
  active-lts: v2.0.x
`)
	_, err := LoadVersions(path)
	require.Error(t, err)
}

func TestLoadVersionsMissingFile(t *testing.T) {
	_, err := LoadVersions(filepath.Join(t.TempDir(), "nope.yaml"))
	require.Error(t, err)
}

// TestRepoVersionsYAML loads the committed versions.yaml so a malformed checked-in
// file fails the suite directly.
func TestRepoVersionsYAML(t *testing.T) {
	v, err := LoadVersions(filepath.Join("..", "..", "versions.yaml"))
	require.NoError(t, err)
	require.Contains(t, v.Labels, "active-lts")
	require.Contains(t, v.Labels, "maint-lts")
	require.Equal(t, "openziti", v.Source.Org)
	require.Equal(t, "ziti", v.Source.Repo)
}
