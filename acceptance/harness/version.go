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

import "golang.org/x/mod/semver"

// Version is the resolved version of the ziti under test: a concrete release tag,
// or a source-built ref.
type Version struct {
	tag         string // release tag (e.g. v2.0.8); for source builds, the ref/SHA
	sourceBuilt bool
}

// AtLeast reports whether the version satisfies the given minimum (with or without
// a leading v). Source-built versions satisfy every minimum, since validating
// unreleased features is the reason source builds exist.
func (v Version) AtLeast(minVersion string) bool {
	if v.sourceBuilt {
		return true
	}
	if minVersion == "" {
		return true
	}
	if minVersion[0] != 'v' {
		minVersion = "v" + minVersion
	}
	return semver.Compare(v.tag, minVersion) >= 0
}

// SourceBuilt reports whether the binary was built from a git ref rather than
// downloaded from a release.
func (v Version) SourceBuilt() bool {
	return v.sourceBuilt
}

// String returns the resolved tag, or a short commit SHA for source builds.
func (v Version) String() string {
	if v.sourceBuilt && len(v.tag) == 40 {
		return v.tag[:12]
	}
	return v.tag
}
