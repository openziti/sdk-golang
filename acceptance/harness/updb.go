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
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	edgeApis "github.com/openziti/sdk-golang/v2/edge-apis"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/stretchr/testify/require"
)

// UpdbIdentity is a created identity that authenticates with a username/password
// (UPDB) credential rather than a client certificate.
type UpdbIdentity struct {
	name     string
	username string
	password string
}

// Name returns the identity's unique name on the controller.
func (i *UpdbIdentity) Name() string { return i.name }

// Username returns the UPDB username (equal to the identity name).
func (i *UpdbIdentity) Username() string { return i.username }

// Password returns the UPDB password set during enrollment.
func (i *UpdbIdentity) Password() string { return i.password }

// CreateUpdbIdentity creates an identity with a UPDB enrollment and completes
// that enrollment via the CLI, setting its password. The username equals the
// identity name. roleAttributes, if given, are set for use in targeted policies.
// The identity is uniquely named per the isolation contract, with best-effort
// cleanup.
func (h *Harness) CreateUpdbIdentity(t testing.TB, base string, roleAttributes ...string) *UpdbIdentity {
	t.Helper()
	unique := uniqueName(t, base)
	password := randomPassword(t)

	idDir := filepath.Join(h.home, "identities")
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		t.Fatalf("creating identities dir: %v", err)
	}
	jwtPath := filepath.Join(idDir, unique+".jwt")

	args := []string{"edge", "create", "identity", unique, "--updb", unique, "--jwt-output-file", jwtPath}
	if len(roleAttributes) > 0 {
		args = append(args, "--role-attributes", strings.Join(roleAttributes, ","))
	}
	h.Cli(t, args...)
	t.Cleanup(func() {
		// best-effort; the whole environment is discarded at teardown regardless
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "identity", unique)
	})

	// complete the UPDB enrollment, which sets the password on the controller
	h.Cli(t, "edge", "enroll", jwtPath, "--username", unique, "--password", password)

	return &UpdbIdentity{name: unique, username: unique, password: password}
}

// NewUpdbSdkContext builds an authenticated ziti.Context for a UPDB identity,
// using its username/password as the primary credential, registering close with
// t.
func (h *Harness) NewUpdbSdkContext(t testing.TB, id *UpdbIdentity) ziti.Context {
	t.Helper()

	ctrlURL := "https://" + h.ctrl.hostPort
	caPool, err := ziti.GetControllerWellKnownCaPool(ctrlURL)
	require.NoError(t, err, "fetching controller ca pool")

	creds := edgeApis.NewUpdbCredentials(id.username, id.password)
	creds.CaPool = caPool

	ctx, err := ziti.NewContext(&ziti.Config{
		ZtAPI:       ctrlURL + "/edge/client/v1",
		Credentials: creds,
	})
	require.NoError(t, err, "creating updb sdk context")
	t.Cleanup(ctx.Close)

	require.NoError(t, ctx.Authenticate(), "authenticating with updb")
	return ctx
}

// randomPassword returns a password meeting typical complexity requirements
// (mixed case, digit, symbol) with random entropy.
func randomPassword(t testing.TB) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating password: %v", err)
	}
	return "Pw1!" + hex.EncodeToString(b)
}
