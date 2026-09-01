# AGENTS.md

Single source of truth for AI coding agents working on this project. Read this before making any changes.

`CLAUDE.md` intentionally delegates here — update this file, not the pointer.

The Snyk DepGraph CLI Extension: a Go module (built on the Snyk go-application-framework) that generates Snyk dependency graphs for a local project across many package-manager ecosystems — pip/uv/pipenv, npm/pnpm/bun, gradle, bazel, cargo, and nuget. Each ecosystem is a self-contained `SCAPlugin` registered with a central orchestrator.

**Scope:** These rules cover the Go source under `pkg/` and `internal/`.

> **Caution:** This repository is intended for internal (Snyk) contributions only at this time.

## Architecture

Every package-manager ecosystem is a plugin implementing the `ecosystems.SCAPlugin` contract (Discover → Resolve → Build → Return). Plugins are registered with a central orchestrator (`pkg/ecosystems/orchestrator`) that resolves dependency ordering and feature-flag gating; each plugin builds a standard Snyk dep-graph and streams results back one at a time. Core dep-graph orchestration lives in `pkg/depgraph`; project-identity types in `pkg/identity`; the Snyk API client and legacy-CLI bridge in `internal/`.

### Hard rules

Every item is a blocking gate — a PR that violates any of these must not merge.

- **Every ecosystem is a plugin implementing `ecosystems.SCAPlugin`** (Discover → Resolve → Build → Return). Add a new ecosystem as a new plugin package and depend on the `SCAPlugin` abstraction; never add ecosystem logic by modifying core or orchestrator code, and keep each plugin's logic inside its own package. Reference: [`pkg/ecosystems/rust/cargo/plugin.go`](pkg/ecosystems/rust/cargo/plugin.go)
- **Build graphs in the standard Snyk dep-graph format via `depgraph.Builder`** and return them on `SCAResult.DepGraph`; populate `PluginResult.ProcessedFiles` with every file you handled so other plugins skip it.
- **Stream each `SCAResult` through the per-graph `OnGraphFunc` callback as it is produced** — never aggregate results into a returned slice. Reference: [`pkg/ecosystems/plugin_interface.go`](pkg/ecosystems/plugin_interface.go) (see #194)
- **Surface resolver failures as typed per-result `SCAResult` errors propagated through the results channel** (missing binary, version too low, unparseable/unprocessable manifest, streaming failure); one ecosystem's failure must not abort the whole run (see #236).
- **Emit deterministic dep-graph output:** sort file lists without mutating the input, and never depend on map iteration order — ranging over a map produces non-deterministic, colliding targets across runs (see #160).
- **Produce one dep graph per workspace package** (each member is a leaf of the root graph and root of its own); never emit a single mega-graph, which misattributes one package's transitive deps as another's vulnerabilities.
- **Identify workspace members by the package manager's authoritative signal** (pnpm's `link:` version prefix, bun's `(requires …)` clause), never by package-name membership — name matching silently skips members when a workspace name collides with a real registry package (see #213).
- **New Go resolvers preserve behavioural parity with the existing TypeScript plugins** (snyk-nuget-plugin, snyk/cli): root-component naming, file-discovery patterns, default root version, pruning. Do not diverge without an explicit decision, and cite the exact upstream plugin version a golden fixture came from (see #235, #230).
- **Fail loudly when a resolver's tool output is missing its expected file marker** — never silently fall back to a default file path.
- **Never add methods or levels to the shared `Logger` interface** — adding to it is a breaking change for every implementor; reuse an existing level (e.g. `Debug`) instead.
- **Keep the module on major version v2:** import it via its `/v2` path, and treat `!` / `BREAKING CHANGE:` as a minor bump — they never trigger a major bump. Split genuine breaking changes to keep the public API backwards-compatible, or raise for discussion before merging (see #199).
- **PR titles must be valid Conventional Commits** (a GitHub Action enforces this) and PRs are merged with **Squash and merge** — the PR title becomes the release commit and drives automated versioning.
- **.NET project identity must set `Identity.TargetRuntime`** and propagate it to workflow metadata; construct identity through the constructor that requires the runtime so it cannot be silently dropped (see #235, #230).
- **When shelling out to bun, pass `--no-env-file` to `bun why`** (bun otherwise loads the repo's `.env`) and require bun ≥ 1.2.19 (see #157).
- **In the bazel plugin, use `bazel query` for target discovery but keep `bazel cquery` for dependency resolution.** `query` and `cquery` return the same target set in the loading phase, so target discovery uses the cheaper `query`; but only `cquery` (the analysis phase) resolves `select()` / platform-conditional deps, which dependency/edge resolution needs for accurate graphs (`go.go`, `jvm.go`). Reference: [`pkg/ecosystems/bazel/query.go`](pkg/ecosystems/bazel/query.go) (see #224)

### Conventions

- Dependencies are injected as constructor params; plugin registration uses functional options (`withFeatureFlagCheck`, `withPluginDependencies`). No DI container, no globals outside the composition root. Reference: [`pkg/ecosystems/orchestrator/registry.go`](pkg/ecosystems/orchestrator/registry.go)
- Each ecosystem package follows the same layout — `plugin.go` (implements `SCAPlugin`) alongside `executor.go`, `depgraph.go`, `types.go` — and is registered centrally in `pkg/ecosystems/orchestrator/registry.go` with explicit dependency ordering (bazel is a dependency of every other plugin) and feature-flag gating.
- Define interfaces next to their consumers (small collaborator interfaces like `cargoRunner` in the consuming package); assert conformance with `var _ Iface = (*T)(nil)`.
- User-facing resolver failures use typed Snyk error-catalog errors (`snyk_errors`, e.g. `NewUnprocessableFileError`, `NewUnparseableManifestError`), not plain `fmt.Errorf` (see #112).
- Reuse the shared cross-ecosystem helpers instead of re-implementing them per ecosystem: the pruned-node contract, edge deduplication (`ConnectNodes` is not idempotent), and the golden-fixture harness (`pkg/ecosystems/scatest`) (see #235).
- Use `identity.ProjectDescriptor` for project identity — the removed `ecosystems.Metadata` type must not be reintroduced — and use the standard keys from the `metadata` package for resolver metadata (see #139).
- Keep legacy-CLI invocation/parsing code in `internal/legacycli` and shared constants/flags in `internal/workflow` to avoid the `pkg/depgraph` ↔ `pkg/ecosystems/legacy` import cycle (see #163, #166).

### Directory layout

| Directory | Purpose |
|-----------|---------|
| `pkg/depgraph` | Core dep-graph workflow: SBOM resolution orchestration, workflow registration, error types, output parsers |
| `pkg/ecosystems` | Per-language SCA plugins implementing `SCAPlugin`, plus the orchestrator, discovery, and argparser |
| `pkg/ecosystems/orchestrator` | `PluginRegistry`: registers plugins with dependency ordering and feature-flag gating |
| `pkg/ecosystems/discovery` | Manifest/lockfile discovery utilities (functional-options, `WalkDir`) |
| `pkg/conversion` | Dep-graph conversion helpers |
| `pkg/identity` | Project descriptor / identity types |
| `internal/legacycli` | Bridge to legacy Snyk CLI resolution |
| `internal/snykclient` | Snyk API client: packages, sbom convert, types |
| `internal/workflow` | Workflow ID constants and CLI flag definitions |

### Danger zone

Treat these areas as high-risk — they have been repeatedly patched:

- **Python plugins** (`pkg/ecosystems/python` — pip/uv/pipenv): the most-fixed area in the repo (see #136, #128, #109 and others).
- **Bun resolver** (`pkg/ecosystems/javascript/bun`): recurring fixes around workspace and env handling (see #157, #156).
- **Gradle resolver** (`pkg/ecosystems/gradle` — init script and dep-graph construction): ordering and output-marker fixes (see #190, #192).

For these, prefer the smallest possible change, add tests before modifying, and ask a human reviewer before landing.

## Code conventions

### Style and formatting

Formatting and linting are enforced by tooling — run `make fmt` (`go fmt` + gofumpt/goimports with local-prefix `github.com/snyk/cli-extension-dep-graph/v2`) and `make lint` (golangci-lint v2.9.0) instead of reasoning about style; they are authoritative. A `gitleaks` pre-commit hook scans for secrets.

### Patterns

- Doc comments explain *why* (rationale, invariants, failure modes), not *what*.
- Sentinel errors are `Err`-prefixed and matched with `errors.Is`; errors crossing package boundaries are wrapped with `%w` (`wrapcheck` is enforced).
- Use `filepath.WalkDir` (not `filepath.Walk`) for directory traversal.
- By convention, directories are concatenated-lowercase single words (`legacycli`, `snykclient`, `remoteconv`); multi-word file basenames are `snake_case` (`output_parser.go`, `common_excludes.go`).

### Best practices for new code

Apply these principles when writing **new** code. Do not refactor existing code to comply unless explicitly asked.

When you touch a file that has existing violations:
1. Write your new code correctly.
2. Leave the surrounding violation untouched.
3. Emit: "⚠️ Legacy debt: [file:line] — [which principle], left alone to avoid scope creep."

- **Single Responsibility Principle (SRP)**
- **Avoid Hasty Abstractions (AHA)**

## Testing

> **Note:** No automated coverage enforcement found in CI or config. CI runs `go test -coverprofile` but does not fail the build on a coverage threshold — coverage is reported, not gated. Consider adding a threshold.

Run all tests with `make test` (`go test ./... -coverprofile cp.out`). Ecosystem integration tests run behind build tags and env vars via dedicated make targets: `make test-python-integration`, `make test-gradle-integration`, `make test-pnpm-integration`, `make test-bazel-jvm-integration`, `make test-bazel-go-integration`.

| Command | What it runs |
|---------|--------------|
| `make test` | Unit tests (`go test ./... -coverprofile cp.out`) |
| `make test-python-integration` (and the other `test-*-integration` targets) | Ecosystem integration tests |

Integration tests are gated behind build tags (`-tags="integration,python|gradle|pnpm"`) and env vars (`BAZEL_JVM_INTEGRATION_TESTS=1`, `BAZEL_GO_INTEGRATION_TESTS=1`). Snapshot/golden tests use `gkampitakis/go-snaps`; regenerate fixtures with `UPDATE_FIXTURES=1` (e.g. `UPDATE_FIXTURES=1 go test -v -tags="integration,gradle" ./pkg/ecosystems/gradle/`).

### AI agent testing protocol

**1. Test-first: fail before pass.**

Before writing implementation, write a test that exercises the new behavior. Run it — it **must
fail** first. A test that passes before the change is testing the wrong thing; discard it and write
another. Implement, then run again. This cycle counts as one attempt; you have **3 attempts** total.
If fail-then-pass cannot be achieved, stop and warn: "Warning: could not achieve
fail-before/pass-after for [test name] — [reason]."

If writing a test before implementation is genuinely not feasible (e.g., the change is in test
scaffolding itself), document the reason explicitly.

**2. Do not add tests for pre-existing untested code you touch.**

When modifying existing code that has no tests, report it: "Warning: [file/function] has no
existing test coverage. This change is unverified." Do **not** add tests for it — that is out of
scope and may introduce incorrect assumptions about existing behavior. Do write tests for any
**new** behavior you add, even if it lives in an existing file.

## Local development

- Requires the Go toolchain pinned in `.tool-versions` / `go.mod` (Go 1.26).
- Install lint tooling with `make install-tools` (installs golangci-lint v2.9.0 into `.bin/`).
- `make lint` runs `.bin/golangci-lint run` — keep the local golangci-lint version identical to CI so results are reproducible.

## Commits and PRs

**Commit format:** `<type>(scope): <description>` (Conventional Commits) — also applies to PR titles, since PRs are squash-merged.
Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert.
Example: `feat(dotnet): resolve SDK-style projects from project.assets.json [CMPA-716] (#235)`
**PR description sections:** Tests written and linted, Documentation written, Commit history is tidy, What this does.

## When in doubt

If you're unsure about a decision that would affect the plugin architecture, dep-graph output contract, or backwards compatibility, ask @snyk/engines_sca-scanners (the CODEOWNERS team) before proceeding.

## Before you finish

Before presenting any change, verify each item below. Do not report work as complete until every applicable item passes.

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] `make fmt` run and output committed
- [ ] Relevant `make test-*-integration` targets pass when touching an ecosystem resolver
- [ ] New code has test coverage (or the "unverified" warning is documented)
- [ ] PR title is a valid Conventional Commit (the GitHub Action check passes)
- [ ] Repository secret scan is clean (`gitleaks` pre-commit hook)

---

## Human review checklist

This file was generated by `/create-agents-md:create-agents-md` as a starting point. Complete these items to finish it:

- [ ] Review test coverage and consider adding a CI coverage threshold (currently reported, not enforced).
- [ ] Confirm the `.NET`/bun/bazel ecosystem rules are still current as those resolvers evolve.
- [ ] Remove this section once all items above are resolved.
