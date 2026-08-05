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

func TestVersionCacheSuffix(t *testing.T) {
	// build-metadata characters are cache-filename safe and preserved
	require.Equal(t, "-ver-v2.0.0+bbolt-mem", versionCacheSuffix("v2.0.0+bbolt-mem"))
	// path separators and other unsafe characters are replaced
	require.Equal(t, "-ver-feature_foo_bar", versionCacheSuffix("feature/foo bar"))
}

func TestVersionLdflags(t *testing.T) {
	sha := "abcdef1234567890abcdef1234567890abcdef12"

	writeGoMod := func(t *testing.T, module string) string {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"),
			[]byte("module "+module+"\n\ngo 1.25.0\n"), 0o600))
		return dir
	}

	t.Run("v2 module path", func(t *testing.T) {
		dir := writeGoMod(t, "github.com/openziti/ziti/v2")
		ldflags, err := versionLdflags(dir, "v2.0.1", sha)
		require.NoError(t, err)
		require.Contains(t, ldflags, "-X github.com/openziti/ziti/v2/common/version.Version=v2.0.1")
		require.Contains(t, ldflags, "-X github.com/openziti/ziti/v2/common/version.Revision=abcdef123456")
	})

	t.Run("v1 module path", func(t *testing.T) {
		dir := writeGoMod(t, "github.com/openziti/ziti")
		ldflags, err := versionLdflags(dir, "v1.6.17", sha)
		require.NoError(t, err)
		require.Contains(t, ldflags, "-X github.com/openziti/ziti/common/version.Version=v1.6.17")
	})

	t.Run("missing go.mod", func(t *testing.T) {
		_, err := versionLdflags(t.TempDir(), "v2.0.1", sha)
		require.Error(t, err)
	})
}
