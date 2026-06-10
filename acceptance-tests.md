# SDK Acceptance Test Framework

## Goal

Exercise the Go SDK for *correctness* against real, running OpenZiti controllers and
routers across multiple versions: active LTS, maintenance LTS, latest release, and
`main`. We also want to test against an arbitrary commit so we can validate SDK
behavior for features that aren't released yet.

Scale and performance testing is explicitly out of scope; that stays in
`ziti/zititest` with fablab. This framework is about behavioral correctness.

## The forcing constraint: out-of-process

A version matrix means the controller and router cannot run in-process. In-process
would pin the SDK to exactly the one controller version it compiles against, which
defeats the purpose. So the shape is fixed at the top:

  the SDK under test (current checkout) talks over the network to a controller+router
  launched from a versioned, external `ziti` binary.

Everything else hangs off that: acquire a binary -> run quickstart -> point the SDK
at it -> assert.

## Decisions

- **Location**: a new top-level `acceptance/` module in sdk-golang, with its own
  `go.mod`, so test-only dependencies (the release downloader, etc.) don't pollute
  the SDK's module graph.
- **Local-only for v1**: run the controller and routers as local processes. The
  user's instinct is right; cloud/fablab realism stays in ziti/zititest. The
  acquisition+bootstrap layer is backend-agnostic, so a fablab backend can be added
  later behind the same harness interface if needed.
- **Separate processes, not single-process quickstart**: the controller and each
  router run as their own process so tests can use multiple routers and start, stop,
  or kill individual components (reconnect, failover, HA). We use quickstart's
  configure-and-exit / PKI building blocks to *generate* a version-correct controller
  config + PKI, then run components separately and add routers on demand via the
  versioned CLI. We do not run `ziti edge quickstart` as an all-in-one black box.
- **Commit the topology, not the config**: config file schemas drift across versions,
  so committing config bytes would force us to hand-maintain cross-version config
  compatibility, the exact version-skew coupling we designed out of the admin layer.
  Instead we commit a declarative, version-agnostic topology spec and let the
  harness materialize it per-version by driving the versioned binary. Certs and
  configs are generated per-run, never committed.
- **Admin setup via the versioned `ziti` CLI**: the CLI of the version under test
  speaks that version's API, so setup stays correct across the matrix with no
  rest_model coupling. We shouldn't have to parse much output; if we find ourselves
  parsing a lot, that's the signal to move that operation to the typed REST/management
  client.
- **Data plane via the SDK under test**: dial/host/listen go through the current
  checkout's `ziti` package. That's the thing we're actually testing.
- **`versions.yaml` as the source of truth** for what `active-lts` / `maint-lts` /
  the matrix resolve to, hand-maintained for now. This may eventually live in the main
  ziti repo, but versions don't change often, so we update it as needed here.
- **Don't import `common/getziti`**: it drags a large chunk of the controller into
  sdk-golang and reintroduces version pinning. The GH-release download logic is small;
  reimplement a self-contained downloader in the acceptance module, reusing getziti's
  approach but not its package.
- **CI triggers**: run on PRs to `main` and on pushes to `main`.

## Architecture

### Layer 1: version resolution + acquisition

A version spec resolves to a concrete binary, with a local cache.

The selector is a **bare commit-ish or label** -- no `commit:`/`branch:` prefixes.
Everything we reference is a commit-ish (a SHA, branch, or tag; a version is just a
release tag), so the resolver classifies the name and picks download-vs-build:

- **Labels** -> download a release binary. `latest` -> highest published semver release
  (drafts/prereleases excluded), from the GitHub releases list (not the repo's "latest"
  tag). `active-lts` / `maint-lts` -> `versions.yaml` (a concrete tag, or a `vM.m.x`
  minor wildcard -> highest released patch of that minor).
- **A release version** (e.g. `v1.6.17`, `v2.0.7`) -> a tag that has a published release
  artifact -> download.
- **Any other ref** (a branch like `connect-v2` or `main`, a non-release tag, or a raw
  SHA) -> resolve to a SHA via git and **build from source** (`go build` the `ziti`
  binary -- a git + go build shellout, since getziti can't).

Classification is deterministic: a label, or a name GitHub has a release artifact for,
downloads; everything else is treated as a git ref and built. So `main` and
`connect-v2` build from source while `v1.6.17` downloads.

**Resolve to an immutable id before any cache lookup.** Every selector is first
resolved to an immutable identity, and the cache is keyed only on that, never on a
mutable selector:

- label / release version / `vM.m.x` wildcard -> the concrete tag (e.g. `v2.0.7`)
- any branch (`main`, `connect-v2`) or non-release tag -> the full commit SHA, via
  `git ls-remote` before lookup
- a raw SHA -> itself

So a branch that has moved upstream becomes a cache miss and rebuilds; nothing stale is
ever served under a stable key like `ziti-connect-v2`. The resolution is a lightweight
remote call (GH API / `git ls-remote`); only the download or build is skipped on a cache
hit. The selector -> resolved-id mapping is logged each run for version attribution.

Cache resolved binaries under e.g. `~/.cache/ziti-acceptance/bin/ziti-<immutable-id>`
(concrete tag or commit SHA) so repeated local runs are instant and CI can cache the
directory.

### Layer 2: bootstrap

Verified against `ziti/run/quickstart.go`:

- `ziti edge quickstart` is **single-process**: the controller and router run as
  goroutines inside the quickstart process (`NewRunControllerCmd`/`NewRunRouterCmd`
  via `go func`), so it can't be decomposed for multi-router or per-component kill.
- `--configure-and-exit` does not just write configs; it **fully boots** (controller
  + cluster/admin init + router enroll + router run), then tears the goroutines down
  but **leaves the home dir intact** (PKI, `ctrl.yaml`, initialized DB with admin,
  router config + enrolled cert). That home is reusable.
- Controller and router are independently runnable from the generated configs:
  quickstart internally runs exactly `ziti controller run <ctrl.yaml>` and
  `ziti router run <router.yaml>`.
- PKI/config/enroll are standard CLI subcommands (`ziti pki create ...`,
  `ziti create config controller`, `ziti create config router edge`,
  `ziti router enroll`), so additional routers are replicable.

**Version-variant init must be delegated.** Modern quickstart initializes the admin
via the go agent doing a raft cluster init (`agentcli.NewAgentClusterInit`, with
`--pid`); older LTS lines predate HA-by-default and init differently. So we delegate
the init to each version's own quickstart rather than hand-rolling it (the same
"let the versioned binary speak for its version" principle as the admin layer).

**Default: separate processes for hygiene.** We never run the controller and a router
in the same process, so SDK-visible behavior is never muddied by in-process
controller/router interactions that wouldn't happen in a real deployment.

The clean realization, which also avoids any reliance on raft
restart-from-persisted-state:

- Run `ziti edge quickstart --no-router` (without `--configure-and-exit`) as a
  **long-lived child process**. With `Routerless=true` it generates PKI + ctrl
  config, starts the controller, runs the version-correct admin/cluster init, then
  blocks; `configureRouter`/`runRouter` return immediately, so the process stays up
  running **only the controller**, no router goroutine. (Overlay policies are skipped
  in routerless mode; tests create their own.)
- Add **every** router as its own separate process via the version-stable CLI steps
  below.

So the SDK only ever talks to a pure controller process plus separate router
processes. The version-variant init stays delegated to quickstart, and the controller
is never restarted, so single-node raft recovery is not on the critical path.

**The routerless contract is verified on the floor version (1.6).** The default rests
on `quickstart --no-router` existing and still performing admin init in routerless
mode. Verified on **v1.6.17** (the maint-lts/1.6.x line, the supported floor): `--no-router`
is present, the process comes up controller-only, the HTTPS endpoint returns 200,
admin login (admin/admin) succeeds, and `ziti edge list identities` works -> routerless
mode does perform admin init. Since every supported line is >= 1.6, the routerless
contract holds across the matrix; there is no pre-1.0/V1-only line to accommodate.

Readiness is still defined as **admin-usable, not just listening** (HTTPS 200 + admin
login + one harmless admin op like `ziti edge list identities`), and build-order step
3 still runs this as a per-version canary, so any future divergence on a new line is
caught as a directed failure rather than an obscure mid-test one. If a future line
ever failed the canary, the fix would be a documented per-version bootstrap adapter
delegated to that version's binary (never hand-rolled init), designed only when needed;
this is a safety net, not a load-bearing gap, given the verified 1.6 floor.

**Version-gated quickstart features.** Verified on 1.6.17:

- `--configure-and-exit` is **absent** (it's a flag; it would appear in `--help` if
  present), so the **controller-restart variant** below requires a newer line.
- the `quickstart join` subcommand is registered **hidden** (`cmd.Hidden = true` in
  quickstart.go), so a `--help` check cannot confirm its presence or flags on 1.6 -- do
  *not* assume it's absent. Re-verify the exact `join` flags when **HA bootstrap** for
  #8 is designed.

Both are P2 concerns, gated to newer lines regardless. We deliberately do **not**
backport `--configure-and-exit` (or any genuinely-missing HA support) to 1.6: nothing
we run on 1.6 needs it (the tests that do are gated to newer lines anyway, and SDK
failover behavior is identical regardless of the controller version it fails over
between), and backporting would test against a 1.6 that isn't deployed in the field
while pinning maint-lts to a specific patch. Version-gating is the cleaner seam.

**Controller-restart variant.** For the (rarer) tests that need to kill and restart
the *controller* itself, on a line that supports it, bootstrap with `ziti edge
quickstart --no-router --configure-and-exit` to leave an initialized home, then drive
the controller directly with `ziti controller run <ctrl.yaml>`. This is the only path
that depends on single-node raft restart-from-persisted-state, and it's opt-in for
exactly the tests that want controller lifecycle control.

Adding a router (version-stable CLI steps, mirrored from quickstart's
`configureRouter`):
`ziti edge create edge-router <name> -o <jwt> --tunneler-enabled --role-attributes public`
-> `ziti create config router edge --routerName <name> --output <yaml>`
-> `ziti router enroll <yaml> --jwt <jwt>` -> `ziti router run <yaml>` (own process).

Details to mirror:
- Config generation reads `ZITI_*` env vars (home, ctrl address/port, PKI paths,
  router name/port); the harness must set these per child command and assign a
  distinct port per router.
- Readiness probes: controller = HTTPS 200 + admin login + one harmless admin op (see
  the bootstrap contract above); router = TCP connect to the router port. TCP-connect
  can return before the router is admin-visible / policy has propagated, so the first
  SDK dial/host after bring-up uses a bounded retry rather than asserting on the first
  attempt; where the CLI exposes it, an admin "router online" check is a stronger gate.
- Home layout is deterministic: `<home>/pki/...`, `<home>/<instanceId>/ctrl.yaml`,
  `<home>/<instanceId>/db/`, `<home>/<instanceId>/<routerName>.yaml`.

Teardown stops every process and removes the tmpdir.

### Layer 2b: topology spec

A test declares the topology it needs as a declarative, version-agnostic spec that the
harness materializes per-version using the Layer 2 steps. The spec is committed and
reviewable; the resulting configs are not.

**The spec is deliberately minimal and grows only when a test we are actually writing
needs more.** v1 supports exactly what Layer 2 can materialize:

- a **single controller** (implicit), and
- **N named edge routers** (each edge + tunneler, as the quickstart CLI path
  produces).

Anything beyond that (multiple controllers / HA, fabric-only routers, explicit
inter-router links) is **not** in v1. `LoadTopology` / `StartTopology` fail fast with
a directed error when a spec asks for them, rather than silently accepting an
unbacked shape. This means a **strict YAML decode** (reject unknown fields, so an
unsupported key like `controllers:` or `links:` errors instead of being ignored) and
rejecting duplicate router names. The role/link/HA mapping gets designed and added
when a test that needs it exists (see the test inventory that drives this), so the
spec never advertises semantics the bootstrap doesn't define.

Sketch (the whole v1 surface):

```yaml
# default: one controller, one edge router
routers:
  - edge1
```

```yaml
# multiple edge routers, e.g. for a failover test that kills one
routers:
  - edge1
  - edge2
```

The default topology is set up once per test package (see Layer 5) and shared; a test
needing more routers declares its own and the harness builds it on the fly. No
committed config or cert fixtures either way.

### Layer 3: admin/setup operations

Drive the versioned `ziti` CLI to create identities, services, policies, posture
checks, revocations, etc. Naturally version-correct and decoupled from rest_model
skew. Promote an operation to the typed management client only when CLI output
parsing gets heavy.

### Layer 4: version gating

A helper, e.g. `RequireMinVersion(t, "1.5.0")`, compares against the version the
harness launched and `t.Skip`s otherwise. `main`/commit builds satisfy every
min-version check (effectively +inf), since unreleased-feature validation is the
reason commit testing exists. A `versions.yaml` entry may declare an effective
version for a commit if finer control is ever needed.

### Authoring sketch

```go
//go:build acceptance

func Test_DialAfterRevocation(t *testing.T) {
    h := harness.Start(t)               // controller-under-test (env-selected version)
    h.RequireMinVersion(t, "1.5.0")     // skips on older lines
    id := h.CreateIdentity(t, "client") // ziti CLI
    ctx := h.NewSdkContext(t, id)       // ziti.NewContext against the running ctrl
    // ... dial/host assertions using the SDK under test
}
```

(See the Implementation plan below for the full API.)

### Layer 5: test scope and sharing

The dominating startup costs are acquiring the binary (solved by the cache) and
controller boot + router enroll + connect (paid regardless of how configs are
produced). The lever for fast effective per-test time is scope: stand up the default
topology once per test package in `TestMain` and share it across tests, the way
ziti's own `tests/` reuses a server. Tests that need a bespoke topology opt into
building their own. This is what makes per-run generation (vs committed fixtures)
cheap enough.

#### Isolation contract

The shared environment is mutable and tests create identities, services, policies,
posture checks, and revocations in it, so the contract that keeps one test from
silently changing another's access is:

- **Unique names per test.** Every helper-created resource is named with the test's
  name plus a short random suffix, so two tests cannot collide on the shared
  controller.
- **Targeted policies only.** A test's policies must reference its own uniquely-named
  entities (explicit `@name` roles, or a per-test attribute that includes the random
  suffix). Never `#all` and never a shared/non-unique attribute, so a policy cannot
  scoop up another test's identities, services, or routers. This is the real
  contamination guard; unique names alone are not enough if a policy grant is broad.
- **Best-effort cleanup.** Helpers register `t.Cleanup` to delete what they created.
  This is best-effort only; the per-package teardown discards the whole environment
  regardless, so a missed cleanup is not fatal, just untidy.
- **Serial by default.** Tests on the shared default harness do not run in parallel.
  A test may opt into parallelism only if it uses solely isolated resource names or
  stands up its own bespoke topology via `StartTopology`. Tests that mutate
  identity-global state (revocation, identity disable/delete) stay serial.
- **Lifecycle tests use a bespoke harness.** Tests that stop, kill, or restart routers
  or controllers (#7, #8) mutate shared process state, not just named entities, so they
  must run on their own `StartTopology` environment, never the package-shared default.

### CI vs local

- **Locally**: `ZITI_ACCEPTANCE_VERSION` selects a single version; default `latest` so
  a bare `go test -tags acceptance ./...` in `acceptance/` just works. To cover several
  versions locally, run the command once per value (CI's matrix does this for you);
  there is no comma-list selector in v1.
- **CI**: a GitHub Actions `matrix` over `[active-lts, maint-lts, latest, main]`, one
  job per version, each setting the selector env, caching the binary dir. The `main`
  job builds from source and so needs the Go toolchain (already present) plus a
  checkout of openziti/ziti at the target ref.

**V2 coverage invariant.** The V1/V2 tests (#2, #3) are runtime-adaptive, so every
released-line job can validly expect V1 and pass; nothing yet *guarantees* the suite
actually exercises V2 + OIDC, which is connect-v2's core risk. So the matrix adds one
**designated V2-coverage job** that runs #2/#3 in **required mode** (set
`ZITI_ACCEPTANCE_REQUIRE_V2=true`): it must have ConnectV2 router capability and
headless OIDC, and it **fails if either is absent** (no adaptive downgrade to a V1
pass). The released-line jobs stay adaptive (probe capability, expect V1, assert
compatibility). Net: released jobs guarantee V1 compatibility, the designated job
guarantees V2 is genuinely exercised.

The designated job selects the **`connect-v2` branch** (a bare ref, built from source),
which must be **pushed to openziti/ziti** so CI can build it -- an unpushed local commit
won't work, and the four released/`main` jobs alone do not satisfy the invariant. Using
the branch (not a pinned SHA) means it tracks the branch HEAD and can't go stale; it
resolves to a concrete SHA before cache lookup like any built ref.
<!-- TODO: once connect-v2 lands on main, point the V2-coverage job at `main` (and at
     the shipping release once it ships). -->

## Implementation plan

### Module layout

```
acceptance/
  go.mod                 # separate module; replace github.com/openziti/sdk-golang => ../
  README.md              # how to run locally and in CI
  versions.yaml          # version matrix source of truth
  harness/               # public, test-facing API
    harness.go           # Harness type, Start, teardown, Cli
    controller.go        # controller process (quickstart --no-router)
    router.go            # Router handle, add/start/stop
    topology.go          # Topology spec types + loader + default
    version.go           # Version type, RequireMinVersion
    setup.go             # admin helpers (identity/service/policy) via CLI
    sdk.go               # NewSdkContext -> ziti.Context (the thing under test)
  internal/
    acquire/             # binary acquisition
      spec.go            # version spec parsing
      download.go        # self-contained GH release downloader
      build.go           # build-from-source for any git ref (branch/tag/SHA)
      cache.go           # local binary cache
    ziticli/             # thin exec wrapper over the versioned ziti binary
      ziticli.go
  tests/
    main_test.go         # TestMain: shared default-topology harness
    smoke_test.go        # first dial/host smoke test
```

The acceptance module has its own `go.mod` so its test-only deps (downloader, yaml)
stay out of the SDK module, and a `replace` directive points it at the local SDK
checkout so it always tests the code in this tree.

Selection is via env: `ZITI_ACCEPTANCE_VERSION` (default `latest`) -- a label
(`latest | active-lts | maint-lts`), a release version (e.g. `v1.6.17`), or any bare
git ref (a branch like `connect-v2` or `main`, a tag, or a SHA). No prefixes.

### Public API (signatures + godoc, no bodies yet)

```go
// Package harness brings up real, versioned OpenZiti controllers and routers as
// local processes so the SDK in this tree can be exercised against them.
package harness

// Harness is a running acceptance environment: one controller plus the routers a
// test asks for, all separate processes, with admin access for setup.
type Harness struct { /* unexported */ }

// StartShared brings up a controller and the default topology for the whole test
// package, for use from TestMain. It is not bound to a *testing.T; the caller runs
// the returned teardown after m.Run(). This is the shared-environment path of Layer 5.
//
//   func TestMain(m *testing.M) {
//       h, teardown, err := harness.StartShared()
//       if err != nil { log.Fatal(err) }
//       shared = h
//       code := m.Run()
//       teardown()
//       os.Exit(code)
//   }
func StartShared() (h *Harness, teardown func(), err error)

// Start brings up a controller and the default topology scoped to a single test,
// registering teardown with t. Use it for a test that wants its own environment
// rather than the package-shared one from StartShared.
func Start(t testing.TB) *Harness

// StartTopology is Start with an explicit topology instead of the default.
func StartTopology(t testing.TB, topo Topology) *Harness

// Version returns the resolved version of the controller under test.
func (h *Harness) Version() Version

// RequireMinVersion skips the test unless the controller is at least min;
// source-built refs (branch/tag/SHA) satisfy every minimum.
func (h *Harness) RequireMinVersion(t testing.TB, min string)

// Cli runs a ziti CLI command against this harness with admin context preconfigured,
// returning stdout and failing t on error.
func (h *Harness) Cli(t testing.TB, args ...string) string

// AddRouter starts an additional edge router as its own process and returns its handle.
func (h *Harness) AddRouter(t testing.TB, name string) *Router

// CreateIdentity creates an identity via the CLI and returns a handle usable for enrollment.
func (h *Harness) CreateIdentity(t testing.TB, name string, opts ...IdentityOpt) *Identity

// CreateService creates a service via the CLI.
func (h *Harness) CreateService(t testing.TB, name string, opts ...ServiceOpt) *Service

// CreateServicePolicy creates a service policy via the CLI.
func (h *Harness) CreateServicePolicy(t testing.TB, name string, opts ...PolicyOpt) *ServicePolicy

// NewSdkContext enrolls id via the acquired ziti CLI (delegated to the versioned
// binary, so test setup never depends on the SDK's own enrollment) and returns an
// authenticated ziti.Context built with the SDK under test, registering close with t.
// The SDK's own enrollment is exercised separately by the dedicated enrollment test.
func (h *Harness) NewSdkContext(t testing.TB, id *Identity) ziti.Context

// Router is a handle to a router process for lifecycle control in failover tests.
type Router struct { /* unexported */ }
func (r *Router) Name() string
func (r *Router) Stop(t testing.TB)  // kill the process
func (r *Router) Start(t testing.TB) // (re)start the process

// Version is a resolved controller version with semver plus a source-built flag.
type Version struct { /* unexported */ }
func (v Version) AtLeast(min string) bool
func (v Version) SourceBuilt() bool
func (v Version) String() string

// Topology is the v1 environment shape: a single (implicit) controller and named
// edge routers. Roles, links, and multiple controllers are intentionally absent
// until a test needs them; see Layer 2b.
type Topology struct {
    Routers []string // edge router names
}

// DefaultTopology is one controller and one edge router.
func DefaultTopology() Topology

// LoadTopology reads a topology spec from a YAML file, failing fast on any field
// outside the v1 surface (multiple controllers, router roles, links).
func LoadTopology(path string) (Topology, error)
```

```go
// Package acquire resolves a version selector to a local ziti binary, downloading a
// GitHub release or building from source as needed, with a local cache.
package acquire

// Spec is a parsed selector: a label (latest/active-lts/maint-lts) or release version
// that downloads a release binary, or any other git ref (branch/tag/SHA) that builds
// from source.
type Spec struct { /* unexported */ }

// ParseSpec parses a ZITI_ACCEPTANCE_VERSION value into a Spec and classifies it:
// labels resolve via versions.yaml (a concrete tag or a vM.m.x minor wildcard); a name
// with a published release artifact downloads; anything else is treated as a git ref to
// build from source.
func ParseSpec(value string) (Spec, error)

// Acquire resolves spec to an immutable id (concrete tag or commit SHA) and returns
// the path to a ziti binary for it, using cacheDir (keyed on that immutable id) to
// avoid re-downloading or rebuilding. A moved mutable selector (main, a wildcard)
// resolves to a new id and so misses the cache rather than serving a stale binary.
func Acquire(spec Spec, cacheDir string) (binPath string, version harness.Version, err error)
```

### versions.yaml schema

```yaml
# 'latest' resolves dynamically to the highest published semver release
# (drafts/prereleases excluded), from the GitHub releases list.
# selectors that aren't a label or release version (branches, tags, SHAs) build from
# source at that ref; only these labels live here.
# each label value is either a concrete tag (e.g. v1.6.17) or a vM.m.x minor wildcard
# (e.g. v2.0.x = highest released patch of that minor, drafts/prereleases excluded).
# wildcards resolve via the GitHub releases API; the resolved concrete tag is what gets
# cached and logged, so each run's actual version is attributable.
# supported floor is 1.6: pre-1.0 is unsupported, and pre-1.6 is not tested here.
# maint-lts = the 1.6.x line, active-lts = the 2.0.x line, latest = 2.1+ (non-LTS).
labels:
  active-lts: v2.0.x   # highest 2.0 patch (minor wildcard)
  maint-lts:  v1.6.17  # pinned concrete tag
source:
  org:  openziti
  repo: ziti
```

### Internal pieces

- **acquire/download.go**: self-contained GitHub release downloader (org/repo from
  versions.yaml, pick the OS/arch asset, download, extract). Reuses getziti's approach
  but not its package, honoring `GITHUB_TOKEN`. Note the asset filename drops the `v`
  prefix the tag carries (tag `v1.6.17` -> asset `ziti-linux-amd64-1.6.17.tar.gz`); to
  avoid guessing the pattern, resolve the asset URL from the release API
  (`/releases/tags/<tag>`) rather than constructing it.
- **acquire/build.go**: `git` fetch of the ref + `go build` of the `ziti` binary for
  any non-release ref (branch/tag/SHA). Needs the Go toolchain (present in CI and
  locally).
- **acquire/cache.go**: cache keyed by the *immutable* resolved id (concrete tag or
  commit SHA, never a mutable selector) under `~/.cache/ziti-acceptance/bin/ziti-<id>`;
  CI caches the dir. Selectors are resolved to that id before lookup. If CI ever runs
  multiple platforms, include `runner.os`/`GOOS`/`GOARCH` in the CI cache key so a
  binary built for one platform isn't reused on another.
- **ziticli/ziticli.go**: exec wrapper that runs the acquired binary with a
  per-harness env (isolated CLI login/config dir so parallel harnesses and the dev's
  own ziti CLI don't collide) and the `ZITI_*` vars the config generators read.

### Port allocation

Pick free ports dynamically per process: bind `:0`, read the assigned port, close,
then pass it via the relevant `ZITI_*` env var (controller edge port, each router
port). This lets multiple routers and parallel harnesses coexist without a fixed port
map. (Resolves the port-allocation open item.)

### Build order

1. Module scaffold: `go.mod` + replace directive, `versions.yaml` + loader. Verify it
   loads and resolves labels.
2. Acquisition (download path): `latest` and explicit `vX.Y.Z`, with cache. Defer
   source-build. Cover release resolution with fixture-based unit tests (unsorted
   releases, prereleases, drafts, `v`-prefix tags, and an older-minor wildcard not on
   the first API page) so a naive "first page / API order" picker is caught.
3. Controller bring-up: launch `quickstart --no-router`, admin-usable readiness probe
   (HTTPS 200 + admin login + harmless admin op), capture admin endpoint/creds; the
   `ziticli` wrapper with isolated login. This doubles as the per-version bootstrap
   contract check: run it against each concrete matrix version early and fail fast with
   a directed message if the delegated routerless path does not yield an admin-usable
   controller.
4. `NewSdkContext`: create identity + enroll **via the ziti CLI** -> `ziti.NewContext`
   with the local SDK. First smoke test: authenticate + `GetServices`. (SDK-side
   enrollment is exercised by its own test, #1b, not by setup.)
5. `AddRouter` (CLI steps) + a real dial/host smoke test through a router.
6. `RequireMinVersion` gating.
7. Source-build path for non-release refs (branch/tag/SHA, e.g. `connect-v2`, `main`).
8. Topology spec loader + `StartTopology`.
9. CI workflow: matrix over the four lines, binary-dir cache, source checkout for the
   `main` job.

## Test inventory and first batch

This is a **general SDK acceptance framework**: it should cover the whole consumer
surface (discovery, dial, host, connection semantics, all posture check types, MFA,
events, enrollment, auth modes), exercised against real controllers/routers across the
version matrix. Cross-version connect-v2/V1 behavior is one important area, not the
whole point.

The batch is derived from a sweep of the SDK-exercising tests in `ziti/tests`, the
usage surface in `sdk-golang/example/`, and a direct audit of the SDK's public API in
`sdk-golang/ziti/**` (so it includes functionality that no existing test or example
exercises). Two framings drive it: the general SDK surface above, and the fact that
every test in `ziti/tests` runs in-process against a single co-built version, so
cross-version behavior can only be covered here.

### Batch

**P0 — every version, core consumer surface + cross-version flagship:**
1. **Smoke + discovery**: enroll (OTT, **via the ziti CLI**) -> authenticate ->
   `GetServices` **asserts the expected services/permissions appear** (not just a
   liveness ping) -> dial + host echo, **exercising half-close (`CloseWrite`) and EOF
   propagation** so the basic stream contract is covered, not just byte echo.
1b. **SDK enrollment round-trip**: the SDK's own `enroll.Enroll` consumes an OTT token
   and yields a usable identity. The *only* place SDK enrollment is the system under
   test; every other test enrolls via the CLI so an SDK enrollment regression can't
   silently fail their setup. (Other enroll modes/key-algs: #9d.)
2. **V1/V2 dial negotiation**: the SDK selects V2 only when the router advertises
   `RouterCapabilityConnectV2` *and* the session is OIDC (otherwise V1; `ForceConnectV1`
   is always V1) -- it is not a function of version. The test detects capability + auth
   mode at runtime, computes the expected path, and asserts the SDK *actually used* it,
   failing if it silently fell back to V1 when V2 was expected. Across the matrix:
   non-capable released lines (1.6.x, 2.0.x; 2.1 likely capable but not guaranteed)
   exercise correct V1 use, and a connect-v2-bearing build (the `connect-v2` branch) exercises real
   V2 negotiation plus the `ForceConnectV1`/legacy fallbacks. **#2 must observe the
   actual negotiated path and fail if it differs from the expected path** -- it must
   never pass via a silent V1 fallback when V2 was expected. The observable is
   `Context.Inspect()`; if `Inspect()` does not distinguish V1 from V2 today, we add it
   there (and/or surface it on a circuit event). The exact mechanism is left to
   implementation (task #2); the fail-on-mismatch requirement is not. A designated CI
   job runs this in required mode so V2 is guaranteed to be exercised somewhere (see the
   V2 coverage invariant in CI vs local).
3. **Auth modes**: dial works under OIDC and legacy (force legacy via `SetUseOidc(false)`),
   and under **ext-JWT** as a primary credential (`LoginWithJWT` / `JwtCredentials`,
   plus `GetExternalSigners`). UPDB has its own item (#6d).

**P1 — high-value general SDK functionality (gated by `RequireMinVersion` where needed):**
4. Revocation enforcement (api-session revoke, identity disable/delete, IssuedBefore
   cutoff; reaper-driven close).
5. **Posture, all check types**: OS, MAC, domain, process, process-multi -- driven via
   the `Set*ProviderFunc` seams -- plus the submitter routing (legacy -> controller vs
   OIDC -> router) and revalidation/enforcement (host-terminator revoke on posture loss,
   dial-circuit teardown on requirement change, negative controls). Batch previously
   named only OS; all types are first-class.
6. api-session token refresh + edge-router propagation, including **refresh-token
   rotation and access-token-only fallback** across multiple refreshes.
6b. **Hosting-path continuity**: bind/listen still uses service sessions and terminators
   (distinct from the sessionless dial path), so verify a hosted terminator survives an
   api-session/token refresh -- the terminator stays registered and the service keeps
   accepting dials across the refresh.
6c. **Service-update propagation + cache invalidation**: add/change/remove a service's
   access (policy edits) after an initial dial and assert the SDK reflects it -- the
   `ServiceAdded/Changed/Removed` events fire and the sessionless service-edge-router
   cache refreshes/invalidates rather than dialing stale data.
6d. **UPDB auth mode**: username/password login + token refresh through the SDK context
   (a common consumer credential path, no topology expansion).
6e. **Connection semantics**: half-close/`CloseWrite`, EOF after peer close, and the
   `AppData` / `SourceIdentifier` / dialer-identity round-trip on accepted conns
   (caller id + app data visible to the host). Core stream + hosting contract.
6f. **Intercept-style dial**: `GetServiceForAddr` matching/scoring, `DialAddr`, and the
   `Dialer` / `DefaultCollection` API with `ConfigTypes` parsing
   (`ClientConfigV1` -> `InterceptV1`). The tunneler-style consumer entry point. Cover
   TCP first; add a UDP intercept match (host.v1/offload) once TCP is in -- no topology
   change needed.

**P2 — broader surface / topology expansion:**
7. Reconnect/failover across **multiple edge routers** (kill one mid-traffic; SDK
   reconnects/fails over; assert `RouterConnected/Disconnected` events; best-latency ER
   selection). Justifies the multi-router topology expansion.
8. **Controller failover**: **multiple controllers** (HA); kill one while dialing; SDK
   fails over to another and emits `ControllerUrlsUpdated`. Justifies the
   multi-controller topology expansion, and exercises the SDK controller-resilience
   paths (controller-swap error matching, token-refresh window, 401 refresh-race) that
   recent SDK work hardened.
9. **Addressable terminators / identity-targeted dial** + sticky + manual-start
   (`AcceptEdge`/`CompleteAccept*`).
9b. **MFA full lifecycle**: `EnrollZitiMfa`/`VerifyZitiMfa`/`RemoveZitiMfa`, partial ->
   full auth via TOTP (`EventMfaTotpCode`, `authenticateMfa`), TOTP-as-posture, and an
   MFA-gated dial. Currently zero coverage of the entire MFA surface.
9c. **Hosting control surface**: live `UpdateCost`/`UpdatePrecedence`/health events,
   HS multi-terminator hosting (`MaxTerminators`, one per ER) + `WaitForNEstablishedListeners`,
   `BindUsingEdgeIdentity` + signed terminator identity, `GetServiceTerminators` paging.
9d. **Enrollment matrix**: `ottca` and CA-auto enrollment, and the key-algorithm matrix
   (RSA-4096 vs EC-P384). Extends #1b's default-alg OTT.
9e. **Event-surface completeness**: assert the remaining event types fire
   (`AuthenticationStatePartial`/`Unauthenticated`, `MfaTotpCode`/`Enrollment`,
   `AuthQuery`, `ControllerUrlsUpdated`). (Would also catch the listener-removal bug
   logged in the task list.)

**P3 — nice-to-have:** api-session save/restore (`ApiSessionJsonWrapper`),
`SetCredentials` runtime swap, `ConnectTimeout`/context-deadline + single dial-retry
semantics.

### Derived setup primitives

The harness admin helpers must cover (P0/P1 first, the rest as their tests land):
identity create + enroll (OTT/UPDB); service (open and posture-roled; with
intercept/host config types for #6f); dial/bind service policies (with semantic and
posture roles); edge-router policy; service-edge-router policy; posture checks
(OS/MAC/domain/process/process-multi); revocation create; identity disable/delete; an
OIDC-vs-legacy context toggle; ext-JWT signer + auth policy (OIDC and ext-JWT login).
P2 setup adds: CA + `ottca` enrollment and key-alg selection (#9d), MFA/TOTP
enrollment + auth-policy-required TOTP (#9b), and sticky/manual-start strategies (#9).
The helper API grows to cover this set as the batch is implemented, not ahead of it.

OIDC must be CI-safe and headless: P0 OIDC uses a local signing key, an
ext-jwt-signer + auth-policy created via the versioned `ziti` CLI, and the SDK's
`LoginWithJWT` with a locally-minted JWT -- not a browser PKCE / device-code flow. The
OIDC setup helper asserts the resulting context actually holds an **OIDC api-session**
(not merely a successful JWT credential) **and that the authenticated identity matches
the one the test intended** before returning, so a misconfigured signer or auth-policy
mapping fails directly instead of surfacing later as a confusing V2 path mismatch or
access error.

### Topology and version implications

- Single controller + single edge router covers all of P0/P1.
- The supported version floor is **1.6** (maint-lts = 1.6.x, active-lts = 2.0.x,
  latest = 2.1+). Pre-1.0 is unsupported; pre-1.6 is not tested here.
- #7 is the first test to use **multiple edge routers** (the capability is already in
  v1 via `Topology.Routers` / `AddRouter`); #8 grows the spec to **multiple
  controllers (HA)**, materialized via quickstart's delegated join flow
  (`ziti edge quickstart join --no-router --cluster-member tls:<ctrl1>`). #8 is gated to
  a newer line (HA needs `--configure-and-exit`, confirmed absent on 1.6; the hidden
  `join` subcommand must be re-verified there); it is also where the controller-restart
  / single-node-raft concern becomes live.
- ConnectV2 is selected by router `RouterCapabilityConnectV2` + OIDC auth mode, not by
  version. connect-v2 is unreleased, so released lines (1.6.x, 2.0.x; 2.1 likely but
  not guaranteed) are non-capable and the SDK must use V1 against them; a
  connect-v2-bearing build (the `connect-v2` branch) is where V2 is exercised. #2 detects
  capability at runtime, so it stays correct whichever release first ships connect-v2.

## Open items

- Topology spec expansion is demand-driven. Multiple edge routers are already in v1
  (`Topology.Routers` / `AddRouter`), so #7 needs no spec change. The one genuine
  expansion is multiple controllers (HA, via quickstart join) for #8; design it when #8
  is written.
- Verify on 2.0.x (when #8 lands): that `--configure-and-exit` exists for the
  controller-restart variant (confirmed absent on 1.6.17), the exact flags of the hidden
  `quickstart join` subcommand (presence not confirmable via `--help`), and single-node
  raft restart-from-persisted-state, which is load-bearing for #8 (controller failover).
  The `join` command shorthand in this doc is illustrative; pin the exact verified flag
  sequence (home, trust-domain,
  instance-id, ports, cluster-member) when #8 is designed.
- How `build.go` obtains the ziti source for a built ref (shallow checkout at the ref
  vs go install of a pseudo-version); decided when build.go is written.
- The V1/V2 test (#2) needs a direct observable for the negotiated path. Plan:
  `Context.Inspect()`; if it does not distinguish V1 from V2, add it there and/or on a
  circuit event (task #2). Mechanism decided at implementation; #2's fail-on-mismatch
  requirement is fixed regardless.
