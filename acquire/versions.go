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

// Package acquire resolves a version selector to a concrete ziti binary. A
// selector is a release version, a label pointing at one, or a git ref (branch,
// tag, or SHA); release selectors download the published artifact, while git-ref
// selectors resolve to a commit and build from source. Results are cached on the
// resolved immutable id (tag or SHA), so a moved selector rebuilds rather than
// serving a stale binary. Callers supply their own source repository and cache
// directory, so any consumer (not just the SDK acceptance suite) can use it.
package acquire

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Source identifies the GitHub repository releases and source are fetched from.
type Source struct {
	Org  string `yaml:"org"`
	Repo string `yaml:"repo"`
}

// Versions is the parsed versions.yaml: the hand-maintained label pointers and the
// source repository.
type Versions struct {
	Labels map[string]string `yaml:"labels"`
	Source Source            `yaml:"source"`
}

// FindVersionsFile walks up from the working directory to locate the acceptance
// module's versions.yaml, so any package or command in the module finds it.
func FindVersionsFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "versions.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("versions.yaml not found walking up from working directory")
		}
		dir = parent
	}
}

// LoadVersions reads and validates versions.yaml from path. It rejects unknown
// fields so an unsupported key fails loudly instead of being silently ignored.
func LoadVersions(path string) (Versions, error) {
	f, err := os.Open(path)
	if err != nil {
		return Versions{}, fmt.Errorf("opening versions file: %w", err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var v Versions
	if err := dec.Decode(&v); err != nil {
		return Versions{}, fmt.Errorf("decoding %s: %w", path, err)
	}
	if v.Source.Org == "" || v.Source.Repo == "" {
		return Versions{}, fmt.Errorf("%s: source.org and source.repo are required", path)
	}
	return v, nil
}
