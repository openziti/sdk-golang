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

//go:build acceptance

package tests

import (
	"os"
	"strings"
	"testing"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"github.com/stretchr/testify/require"
)

// Test_SdkEnrollment is P0 #1b: the SDK's own enroll.Enroll consumes an OTT token
// and yields a usable identity. This is the only place SDK enrollment is the
// system under test; every other test enrolls via the versioned CLI so an SDK
// enrollment regression can't silently fail their setup.
func Test_SdkEnrollment(t *testing.T) {
	h := shared
	name, jwtPath := h.CreateUnenrolledIdentity(t, "sdk-enroll")

	jwtBytes, err := os.ReadFile(jwtPath)
	require.NoError(t, err)

	token, _, err := enroll.ParseToken(strings.TrimSpace(string(jwtBytes)))
	require.NoError(t, err)

	var keyAlg ziti.KeyAlgVar
	require.NoError(t, keyAlg.Set("RSA"))

	cfg, err := enroll.Enroll(enroll.EnrollmentFlags{Token: token, KeyAlg: keyAlg})
	require.NoError(t, err)

	// the enrolled config must produce a working, authenticated context
	ctx, err := ziti.NewContext(cfg)
	require.NoError(t, err)
	t.Cleanup(ctx.Close)

	require.NoError(t, ctx.Authenticate())

	current, err := ctx.GetCurrentIdentity()
	require.NoError(t, err)
	require.NotNil(t, current.Name)
	require.Equal(t, name, *current.Name)
}
