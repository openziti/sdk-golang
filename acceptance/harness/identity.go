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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Identity is a created-and-enrolled identity, usable to build an SDK context.
type Identity struct {
	name     string
	jsonPath string
}

// Name returns the identity's unique name on the controller.
func (i *Identity) Name() string {
	return i.name
}

// ConfigPath returns the path of the enrolled identity JSON file.
func (i *Identity) ConfigPath() string {
	return i.jsonPath
}

// CreateIdentity creates an identity via the versioned CLI and enrolls it via the
// CLI as well (per the setup contract, SDK enrollment is exercised only by its
// dedicated test). The identity is uniquely named per the isolation contract and
// best-effort deleted via t.Cleanup. roleAttributes, if given, are set on the
// identity for use in targeted policies.
func (h *Harness) CreateIdentity(t testing.TB, name string, roleAttributes ...string) *Identity {
	t.Helper()
	unique := uniqueName(t, name)

	idDir := filepath.Join(h.home, "identities")
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		t.Fatalf("creating identities dir: %v", err)
	}
	jwtPath := filepath.Join(idDir, unique+".jwt")
	jsonPath := filepath.Join(idDir, unique+".json")

	args := []string{"edge", "create", "identity", unique, "--jwt-output-file", jwtPath}
	if len(roleAttributes) > 0 {
		args = append(args, "--role-attributes", strings.Join(roleAttributes, ","))
	}
	h.Cli(t, args...)
	t.Cleanup(func() {
		// best-effort; the whole environment is discarded at teardown regardless
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "identity", unique)
	})

	h.Cli(t, "edge", "enroll", jwtPath, "--out", jsonPath)
	return &Identity{name: unique, jsonPath: jsonPath}
}

var nameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// uniqueName builds a per-test unique resource name: the test name, the given
// base, and a short random suffix, so tests sharing an environment cannot collide.
func uniqueName(t testing.TB, base string) string {
	prefix := nameSanitizer.ReplaceAllString(t.Name(), "-")
	const maxPrefix = 40
	if len(prefix) > maxPrefix {
		prefix = prefix[len(prefix)-maxPrefix:]
	}
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	return fmt.Sprintf("%s-%s-%s", prefix, base, hex.EncodeToString(suffix))
}
