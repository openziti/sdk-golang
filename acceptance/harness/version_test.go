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

	"github.com/stretchr/testify/require"
)

func TestVersionAtLeast(t *testing.T) {
	v := Version{tag: "v1.6.17"}
	require.True(t, v.AtLeast("1.6.17"))
	require.True(t, v.AtLeast("v1.6.0"))
	require.True(t, v.AtLeast("")) // no minimum
	require.False(t, v.AtLeast("1.7.0"))
	require.False(t, v.AtLeast("v2.0.0"))

	src := Version{tag: "connect-v2", sourceBuilt: true}
	require.True(t, src.AtLeast("99.0.0"), "source builds satisfy every minimum")
	require.True(t, src.SourceBuilt())
}
