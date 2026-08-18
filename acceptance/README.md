# SDK Acceptance Tests

This module tests the SDK in this tree against *real* OpenZiti controllers and
routers across multiple versions: the LTS lines, the latest release, and (planned)
branches or commits built from source. The controller and routers run as separate
local child processes; the SDK side of every test runs against the local checkout
via this module's `replace` directive.

Design and rationale live in [acceptance-tests.md](../acceptance-tests.md).

## Quick start

```bash
cd acceptance
go test -tags acceptance ./...
```

That downloads the latest ziti release (cached after the first run), boots a
controller, and runs the acceptance suite against it.

Without the `acceptance` build tag, `go test ./...` runs only the fast,
network-free unit tests (selector parsing, version resolution against fixtures,
and similar). The tagged suite is the one that talks to real controllers.

## Selecting the ziti version

`ZITI_ACCEPTANCE_VERSION` picks what the suite runs against (default: `latest`):

```bash
ZITI_ACCEPTANCE_VERSION=maint-lts  go test -tags acceptance ./...   # 1.6.x line
ZITI_ACCEPTANCE_VERSION=active-lts go test -tags acceptance ./...   # 2.0.x line
ZITI_ACCEPTANCE_VERSION=v1.6.17    go test -tags acceptance ./...   # exact release
```

Selectors are bare names, no prefixes:

| Selector | Meaning |
|---|---|
| `latest` | highest published release (drafts/prereleases excluded) |
| `active-lts`, `maint-lts` | labels from [versions.yaml](versions.yaml) (a pinned tag or a `vM.m.x` wildcard meaning "highest patch of that minor") |
| `v1.6.17` (any release version) | that release |
| `main`, `connect-v2`, a SHA (any other git ref) | built from source — **not yet implemented** |

Labels and wildcards re-resolve on every run, but binaries are cached by the
concrete resolved version, so a moved label is picked up while repeat runs stay
fast. Narrow to a single test the usual way:

```bash
ZITI_ACCEPTANCE_VERSION=maint-lts go test -tags acceptance ./harness/ -run Test_ControllerBringUp -v
```

## Running the whole matrix

One process tests one version, so covering several versions means one run per
selector. The matrix runner does that with a summary:

```bash
go run ./cmd/matrix                          # all selectors: versions.yaml labels + latest
go run ./cmd/matrix maint-lts latest         # a subset
go run ./cmd/matrix -fail-fast               # stop at the first failing version
go run ./cmd/matrix -- -run Test_Smoke -v    # one test across every version
```

```
==== matrix summary ====
active-lts   PASS  (1m12s)
maint-lts    PASS  (58s)
latest       PASS  (1m03s)
```

## Binary cache

Downloaded (and, later, source-built) ziti binaries land in
`<user cache dir>/ziti-acceptance/bin/ziti-<version>-<goos>-<goarch>`, keyed by the
concrete resolved version and the platform the binary was produced for. Override the
location with `ZITI_ACCEPTANCE_CACHE`. Deleting the directory is always safe; the next
run re-downloads.

Binaries target the platform the harness runs on unless a caller passes
`acquire.WithPlatform`, which release selectors honor when picking an asset and git-ref
selectors honor by cross-building. Since the platform is part of the entry name, one
version can be cached for several platforms at once and a binary is never handed to a
platform that cannot run it.

`GITHUB_TOKEN`, if set, is used for GitHub API calls. Without it, GitHub's
unauthenticated limit (60 requests/hour per IP) can bite after a few matrix runs;
failures say so explicitly and name the fix. Version resolution is memoized per
test process, and pinned versions already present in the binary cache skip the
API entirely, so token-less use works for normal development.

## Opt-in live tests

`ZITI_ACCEPTANCE_LIVE=1` enables the (untagged) test that exercises acquisition
against the real GitHub API end to end, catching drift between our assumptions and
the actual release/asset layout:

```bash
ZITI_ACCEPTANCE_LIVE=1 go test ./internal/acquire/ -run TestAcquireLive -v
```

## Layout

| Path | Purpose |
|---|---|
| `harness/` | public test-facing API: start environments, create identities, build SDK contexts |
| `internal/acquire/` | version selector parsing/resolution, release download, binary cache |
| `internal/ziticli/` | exec wrapper over the acquired ziti binary with isolated CLI state |
| `cmd/matrix/` | the multi-version runner |
| `versions.yaml` | label -> version pointers and the source repository |

## Notes

- Tests on a shared environment follow the isolation contract (unique per-test
  resource names, targeted policies only, serial by default); see the design doc.
- The harness isolates all ziti CLI state under the test environment's directory
  (`ZITI_CONFIG_DIR`), so it never touches `~/.config/ziti/ziti-cli.json`.
- Supported platforms: linux and darwin (release archives are tar.gz; zip/windows
  is not supported).
