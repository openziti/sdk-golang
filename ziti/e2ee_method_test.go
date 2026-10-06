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

package ziti

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"testing"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// e2eeMethodContext returns a context whose controller capabilities are already loaded, so
// e2eeMethod never calls the controller.
func e2eeMethodContext(configured edge.CryptoMethod, controllerFips bool) *ContextImpl {
	ctrl := &CtrlClient{}
	ctrl.capabilitiesLoaded.Store(true)
	ctrl.controllerFipsMode.Store(controllerFips)
	return &ContextImpl{options: &Options{E2EEMethod: configured}, CtrlClt: ctrl}
}

func TestE2eeMethod(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("covered by TestE2eeMethodFipsProcess")
	}
	tests := []struct {
		name           string
		configured     edge.CryptoMethod
		controllerFips bool
		want           edge.CryptoMethod
	}{
		{"default", edge.CryptoMethodLibsodium, false, edge.CryptoMethodLibsodium},
		{"configured tls", edge.CryptoMethodTLS, false, edge.CryptoMethodTLS},
		{"controller FIPS_MODE", edge.CryptoMethodLibsodium, true, edge.CryptoMethodTLS},
		{"configured tls and FIPS_MODE", edge.CryptoMethodTLS, true, edge.CryptoMethodTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, e2eeMethodContext(tt.configured, tt.controllerFips).e2eeMethod())
		})
	}
}

// TestDialCryptoMethodUnencrypted verifies that a dial to a service without encryption does not ask
// the controller for its capabilities. The controller client has no API, so a call would panic.
func TestDialCryptoMethodUnencrypted(t *testing.T) {
	req := require.New(t)
	ctx := &ContextImpl{options: &Options{E2EEMethod: edge.CryptoMethodTLS}, CtrlClt: &CtrlClient{}}
	encrypted := false

	req.Equal(edge.CryptoMethodLibsodium, ctx.dialCryptoMethod(&rest_model.ServiceDetail{}))
	req.Equal(edge.CryptoMethodLibsodium, ctx.dialCryptoMethod(&rest_model.ServiceDetail{EncryptionRequired: &encrypted}))
}

func TestDialCryptoMethodEncrypted(t *testing.T) {
	encrypted := true
	ctx := e2eeMethodContext(edge.CryptoMethodLibsodium, true)
	require.Equal(t, edge.CryptoMethodTLS, ctx.dialCryptoMethod(&rest_model.ServiceDetail{EncryptionRequired: &encrypted}))
}

// TestE2eeMethodFipsProcess checks that a process running Go's FIPS 140-3 module picks tls even
// when libsodium is configured and the controller does not report FIPS_MODE. FIPS mode is fixed
// at process start, so the check runs in a child test process with GODEBUG=fips140=on.
func TestE2eeMethodFipsProcess(t *testing.T) {
	const childEnv = "ZITI_E2EE_METHOD_FIPS_CHILD"
	if os.Getenv(childEnv) != "" {
		require.True(t, fips140.Enabled())
		require.Equal(t, edge.CryptoMethodTLS, e2eeMethodContext(edge.CryptoMethodLibsodium, false).e2eeMethod())
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestE2eeMethodFipsProcess$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "--- PASS: TestE2eeMethodFipsProcess")
}
