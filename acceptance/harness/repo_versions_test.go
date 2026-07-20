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

package harness

import (
	"testing"

	"github.com/openziti/sdk-golang/acquire"
	"github.com/stretchr/testify/require"
)

// TestRepoVersionsYAML loads the committed versions.yaml so a malformed checked-in
// file fails the suite directly.
func TestRepoVersionsYAML(t *testing.T) {
	path, err := acquire.FindVersionsFile()
	require.NoError(t, err)

	v, err := acquire.LoadVersions(path)
	require.NoError(t, err)
	require.Contains(t, v.Labels, "active-lts")
	require.Contains(t, v.Labels, "maint-lts")
	require.Equal(t, "openziti", v.Source.Org)
	require.Equal(t, "ziti", v.Source.Repo)
}
