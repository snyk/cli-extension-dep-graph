# Yarn SCA Plugin

Builds dependency graphs for Yarn projects by shelling out to the user's
installed `yarn` and parsing its CLI output. Replaces the lockfile-only path
through `nodejs-lockfile-parser` so we get correctness from yarn itself rather
than re-implementing its semantics.

**No install, no `node_modules`, no project-dir mutation, no network** — the
plugin runs yarn in read-only mode and walks the lockfile only. Berry's
metadata writes are redirected to a tmp dir so the user's project is
untouched, and `YARN_ENABLE_NETWORK=false` is set on the Berry path so a scan
can't fetch packages even if a future yarn version tries.

**Not yet wired into the orchestrator** — the plugin package exists and is
fully tested, but registration in `pkg/ecosystems/orchestrator/` is deferred
to a follow-up to avoid colliding with other resolver work in flight. Wiring
will mirror bun's pattern: a new `FlagYarnResolver` in `orchestrator/flags.go`
plus a `r.register(yarn.Plugin{}, withFeatureFlagCheck(FlagYarnResolver),
withPluginDependencies("bazel"))` call in `NewDefaultPluginRegistry`.

## Supported yarn versions

| Family  | Versions    | Command                                                                                                                      | Project mutation | Network |
|---------|-------------|------------------------------------------------------------------------------------------------------------------------------|------------------|---------|
| Classic | 1.x         | `yarn list --depth=Infinity --json --frozen-lockfile --no-progress --non-interactive`                                        | none             | none    |
| Berry   | 2.x / 3.x / 4.x | `yarn info --all --recursive --json` with `YARN_GLOBAL_FOLDER`, `YARN_ENABLE_GLOBAL_CACHE=true`, `YARN_INSTALL_STATE_PATH` redirected to a tmp dir and `YARN_ENABLE_NETWORK=false` | none             | disabled |

Version detection runs `yarn --version` inside the project dir, so corepack-
managed projects (those with a `packageManager` field in `package.json` or a
`yarnPath` in `.yarnrc.yml`) get their project-pinned yarn — not the system
default.

## Install-free + offline-capable verification

The "no `node_modules`, no network" claim was validated on real fixtures
during the initial spike:

- v1: `yarn list --frozen-lockfile` reads `yarn.lock` directly. Confirmed
  against `nodejs-lockfile-parser/test/jest/dep-graph-builders/fixtures/yarn-lock-v1/real/one-dep`
  — output matched the existing fixture exactly with the project dir
  unmodified, and re-run with `HTTPS_PROXY=127.0.0.1:1` to confirm no
  network access.
- Berry: `yarn info -AR --json` writes `.yarn/install-state.gz` and
  `.yarn/cache/` into the project dir by default. The three env vars above
  redirect all of it to a tmp dir that's `os.RemoveAll`'d after the
  subprocess exits. `YARN_ENABLE_NETWORK=false` enforces the offline
  contract — verified empirically against a yarn 3.6.4 project with a fresh
  empty cache, where `yarn info` walks the lockfile and emits the full
  resolved tree without touching the network.

The `TestAcceptance_Classic` test in `acceptance_test.go` asserts the
install-free contract continuously: after running the plugin, the staged
fixture dir must contain only `package.json` + `yarn.lock`.

## Architecture

| File              | Role                                                                                                |
|-------------------|-----------------------------------------------------------------------------------------------------|
| `plugin.go`       | `Plugin` struct, `SCAPlugin` impl, lockfile discovery, per-file orchestration, error wrapping       |
| `executor.go`     | `yarnRunner` interface + `yarnCmdExecutor`; version detection + command branching + tmp redirection |
| `depgraph.go`     | DFS builder; workspace packages are stop-set leaves in non-owner graphs                             |
| `info_parser.go`  | Berry NDJSON parser (`yarn info`)                                                                   |
| `list_parser.go`  | Classic tree-JSON parser (`yarn list`) with semver disambiguation of child specifiers               |
| `package_json.go` | Reads root + workspace `package.json` (both `["packages/*"]` and `{packages: [...]}` shapes)        |
| `types.go`        | `forwardGraph`, `parsedOutput`, `workspaceInfo` shared types                                        |

Both parsers feed the same `parsedOutput` so `depgraph.go` doesn't care which
yarn family produced it.

## Locator handling

Berry locators carry protocol prefixes and peer-virtualisation infixes:

- `name@npm:1.2.3` — regular published package
- `name@workspace:packages/x` — workspace member; `:.` marks the root
- `name@virtual:<hash>#npm:1.2.3` — peer-virtualised; the `@virtual:.*#`
  infix is stripped so all virtualisations collapse onto a single graph node
- `name@file:./local`, `name@patch:base#diff.patch` — preserved verbatim;
  their payload encodes meaningful information that vuln matching may need

Graph node IDs keep the raw locator (so multiple resolutions of the same
package don't collide), while `PkgInfo.Version` strips the `npm:` prefix so
downstream consumers see clean `4.3.1`-style versions.

## Workspaces

Both families emit one `SCAResult` per workspace package plus one for the
root. In each workspace's own dep graph, sibling workspace packages appear
as leaves — their subtrees live only in their own graph — so vuln reports
don't double-count.

Classic v1 synthesizes workspace IDs in Berry's `name@workspace:dir` form so
the depgraph stop-set logic works uniformly across families.

## Testing

```bash
# Unit tests (mocked executor, captured fixtures) — no yarn required
go test ./pkg/ecosystems/javascript/yarn/...

# Acceptance — requires yarn 1.x in PATH (v1) or yarn 3.x via corepack (Berry, currently skipped)
go test -run TestAcceptance ./pkg/ecosystems/javascript/yarn/...
```

Fixtures captured from real yarn runs live under `testdata/fixtures/`. The
two seed fixtures (`classic-simple/`, `berry-simple/`) reuse outputs from
`nodejs-lockfile-parser/test/jest/cli-parsers/fixtures/`.

## Known gaps

- **Berry acceptance fixtures** — `TestAcceptance_Berry` is a placeholder
  pending fixtures per Berry major (2/3/4). CI will need `corepack enable`
  before the suite runs.
- **v1 workspace globs** — only `*` is expanded (via `filepath.Glob`). Deeper
  patterns like `**/foo` aren't picked up. The deduped root graph still
  resolves correctly; only the per-workspace graph emission is skipped for
  those.
- **Tag and URL specifiers** — `yarn list` specifiers like `lodash@latest` or
  `pkg@git+https://...` aren't semver-resolved; they're surfaced verbatim as
  graph nodes so the package isn't lost from the report.
