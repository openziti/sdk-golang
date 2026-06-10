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
	"fmt"
	"regexp"
)

// SpecKind classifies how a selector is acquired.
type SpecKind int

const (
	// SpecLabel is a moving label resolved against versions.yaml or, for "latest",
	// the GitHub release list. It resolves to a release tag and downloads.
	SpecLabel SpecKind = iota
	// SpecReleaseVersion is a concrete release version (e.g. v1.6.17) downloaded
	// from its GitHub release.
	SpecReleaseVersion
	// SpecGitRef is any other git ref (a branch, a non-release tag, or a SHA) that
	// is resolved to a commit and built from source.
	SpecGitRef
)

// LabelLatest is the built-in label for the highest published release. It is not
// stored in versions.yaml.
const LabelLatest = "latest"

// Spec is a parsed, classified version selector.
type Spec struct {
	Raw   string   // the original selector string
	Kind  SpecKind // how it is acquired
	Label string   // the label name, set only when Kind == SpecLabel
}

// releaseVersionRe matches a concrete release version such as v1.6.17 or
// v2.0.7-rc1. A leading v is required, since ziti release tags carry it.
//
// This is deliberately stricter than semver.IsValid, which also accepts partial
// versions like v1 and v1.6. Those must classify as git refs (e.g. a v1.6 branch),
// so classification requires the full vMAJOR.MINOR.PATCH shape.
var releaseVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// ParseSpec classifies value into a Spec against cfg. It is a pure syntactic
// classification: "latest" and any label in cfg are labels; a value shaped like a
// release version is a release version; anything else is a git ref to build from
// source. Whether the release or ref actually exists is confirmed later, during
// resolution.
func ParseSpec(value string, cfg Versions) (Spec, error) {
	if value == "" {
		return Spec{}, fmt.Errorf("empty version selector")
	}
	if value == LabelLatest {
		return Spec{Raw: value, Kind: SpecLabel, Label: value}, nil
	}
	if _, ok := cfg.Labels[value]; ok {
		return Spec{Raw: value, Kind: SpecLabel, Label: value}, nil
	}
	if releaseVersionRe.MatchString(value) {
		return Spec{Raw: value, Kind: SpecReleaseVersion}, nil
	}
	return Spec{Raw: value, Kind: SpecGitRef}, nil
}
