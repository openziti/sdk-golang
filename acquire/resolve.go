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
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// ResolvedID is the immutable identity a spec resolves to: a concrete release tag
// for downloads, or a full commit SHA for source builds.
type ResolvedID struct {
	Tag         string
	SourceBuilt bool
}

// ErrBuildFromSource indicates the spec is a git ref that must be resolved to a
// commit and built from source, which ResolveTag does not handle; the acquisition
// layer routes such specs to the source-build path instead.
var ErrBuildFromSource = errors.New("git ref selector builds from source, not via release resolution")

// ResolveTag resolves a download-kind spec (a label or release version) to a
// concrete release tag, using lister for the dynamic cases. Drafts are always
// excluded; prereleases are excluded when picking the highest of a set (latest or a
// wildcard) but honored for an explicit version pin. Git-ref specs return
// ErrBuildFromSource.
func ResolveTag(ctx context.Context, spec Spec, cfg Versions, lister ReleaseLister) (ResolvedID, error) {
	switch spec.Kind {
	case SpecGitRef:
		return ResolvedID{}, ErrBuildFromSource
	case SpecReleaseVersion:
		return resolveConcrete(ctx, spec.Raw, lister)
	case SpecLabel:
		if spec.Label == LabelLatest {
			tag, err := highest(ctx, lister, func(string) bool { return true })
			if err != nil {
				return ResolvedID{}, fmt.Errorf("resolving latest: %w", err)
			}
			return ResolvedID{Tag: tag}, nil
		}
		val, ok := cfg.Labels[spec.Label]
		if !ok {
			return ResolvedID{}, fmt.Errorf("unknown label %q", spec.Label)
		}
		return resolveLabelValue(ctx, spec.Label, val, lister)
	default:
		return ResolvedID{}, fmt.Errorf("unhandled spec kind %d", spec.Kind)
	}
}

// wildcardRe matches a vM.m.x minor wildcard label value, e.g. v2.0.x.
var wildcardRe = regexp.MustCompile(`^v\d+\.\d+\.x$`)

// resolveLabelValue resolves a versions.yaml label value, which is either a concrete
// tag or a vM.m.x minor wildcard.
func resolveLabelValue(ctx context.Context, label, val string, lister ReleaseLister) (ResolvedID, error) {
	if strings.HasSuffix(val, ".x") {
		if !wildcardRe.MatchString(val) {
			return ResolvedID{}, fmt.Errorf("label %q: invalid wildcard value %q", label, val)
		}
		majorMinor := strings.TrimSuffix(val, ".x")
		tag, err := highest(ctx, lister, func(tag string) bool { return semver.MajorMinor(tag) == majorMinor })
		if err != nil {
			return ResolvedID{}, fmt.Errorf("label %q (%s): %w", label, val, err)
		}
		return ResolvedID{Tag: tag}, nil
	}
	id, err := resolveConcrete(ctx, val, lister)
	if err != nil {
		return ResolvedID{}, fmt.Errorf("label %q: %w", label, err)
	}
	return id, nil
}

// resolveConcrete confirms tag exists as a non-draft release and returns it.
func resolveConcrete(ctx context.Context, tag string, lister ReleaseLister) (ResolvedID, error) {
	rels, err := lister.List(ctx)
	if err != nil {
		return ResolvedID{}, err
	}
	for _, r := range rels {
		if r.Tag == tag && !r.Draft {
			return ResolvedID{Tag: tag}, nil
		}
	}
	return ResolvedID{}, fmt.Errorf("release %q not found", tag)
}

// highest returns the tag of the highest-semver release satisfying pred, excluding
// drafts and prereleases.
func highest(ctx context.Context, lister ReleaseLister, pred func(tag string) bool) (string, error) {
	rels, err := lister.List(ctx)
	if err != nil {
		return "", err
	}
	var bestTag string
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		if !semver.IsValid(r.Tag) || semver.Prerelease(r.Tag) != "" {
			continue
		}
		if !pred(r.Tag) {
			continue
		}
		if bestTag == "" || semver.Compare(bestTag, r.Tag) < 0 {
			bestTag = r.Tag
		}
	}
	if bestTag == "" {
		return "", fmt.Errorf("no matching release found")
	}
	return bestTag, nil
}
