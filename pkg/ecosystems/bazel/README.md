# Bazel Dependency Graph Resolver

## Overview

This package builds Snyk dependency graphs from Bazel workspaces. Bazel is a polyglot build system whose dependency model is expressed as a graph of *targets* rather than language-native package coordinates, so vulnerability scanning requires a two-step translation:

1. Ask Bazel itself which targets are reachable from a chosen entry point.
2. Map those Bazel target labels back to the ecosystem coordinates Snyk recognises (Maven `group:artifact:version`, Go `module/path` + version, etc.).

The package is structured around a small `bazelDependencyResolver` interface (`resolver.go`) with one implementation per supported ruleset:

| Language | Ruleset | Lockfile / source-of-truth | Implementation |
| --- | --- | --- | --- |
| JVM (Java, Kotlin, Scala, Android) | [`rules_jvm_external`](https://github.com/bazel-contrib/rules_jvm_external) | `maven_install.json` | `jvm.go` |
| Go | [`rules_go`](https://github.com/bazel-contrib/rules_go) + [`gazelle`](https://github.com/bazel-contrib/bazel-gazelle) | `go.mod` | `go.go` |

The plugin entry point (`plugin.go`) selects a resolver based on CLI flags, walks the discovered targets, and emits one `SCAResult` per target.

## Flags

| Flag | Effect |
| --- | --- |
| `--bazel-jvm` | Enable the `rules_jvm_external` resolver. |
| `--bazel-go` | Enable the `rules_go` resolver. Mutually exclusive with `--bazel-jvm`. |
| `--bazel-target-query` | Override the default Bazel target-discovery query (see below). |
| `--bazel-max-targets` | Maximum number of targets the resolver will process per invocation. Defaults to `1000`; set to `0` to disable the ceiling. |

Without one of `--bazel-jvm` or `--bazel-go`, the plugin no-ops — Bazel projects look like ordinary directories on disk, so there is no reliable heuristic for auto-detection and we keep the trigger explicit.

### Target ceiling

The default queries (`kind('java_binary', //...)` / `kind('go_binary', //...)`) are pre-filtered to deployable entry points, which keeps the result set bounded on most projects. A loose `--bazel-target-query` (e.g. `//...`) can enumerate orders of magnitude more targets and lead to runaway scans. To guard against accidental target explosion, the plugin caps the discovered target count at `1000` and returns an error if exceeded. Raise the ceiling with `--bazel-max-targets=N`, or disable it entirely with `--bazel-max-targets=0` when you genuinely want every target evaluated.

## How resolution works

Both resolvers share the same overall shape:

1. **Build the lookup table.** When the resolver is constructed, it reads the ecosystem-native source-of-truth for versions (`maven_install.json` for JVM, `go.mod` for Go) and indexes it by the *Bazel repository / target name* that the corresponding rules would generate. This means we never have to run `bazel build` to learn versions — they are already pinned in files the user committed.
2. **Find targets.** `findTargets` runs `bazel cquery <query> --output=jsonproto`. The default query is `kind('java_binary', //...)` for JVM and `kind('go_binary', //...)` for Go; both can be overridden via `--bazel-target-query`. Each top-level result becomes a root in its own dep-graph.
3. **Query transitive deps.** For each target, `bazel cquery 'deps(<target>)' --output=jsonproto` returns every rule reachable from that target, along with its label-typed attributes. We extract the language-relevant attributes only (`deps`, `runtime_deps`, `exports` for JVM; `deps`, `embed` for Go) to avoid polluting the graph with toolchain / platform edges that Bazel also reports as "dependencies".
4. **Walk the label graph.** Starting from the root target label, we BFS through the label-to-label edges. Each label is converted into a `PkgInfo` via the lookup table built in step 1; labels that don't match any external repo (i.e. first-party Bazel targets, generated rules, toolchains) are kept verbatim in the graph as intermediate nodes — they have no version, but they preserve the *path* a vulnerable dependency was pulled in through, which is useful when triaging.

All `bazel` subprocesses are dispatched through `query.go`, which uses `--output=jsonproto` and decodes a minimal subset of the [Bazel Build Event Protocol's](https://bazel.build/remote/bep) target message. Only `rule.name` and `rule.attribute` are read; everything else is ignored.

## JVM resolver (`jvm.go`)

### Lockfile-driven version lookup

`rules_jvm_external` writes a `maven_install.json` lockfile next to the `MODULE.bazel` / `WORKSPACE` file. We read it once at resolver construction time and build a `label → PkgInfo` map.

The trick is that the *keys* in `maven_install.json` are Maven coordinates (`com.google.guava:guava`), while the *labels* Bazel emits in `cquery` output are mangled identifiers (`@maven//:com_google_guava_guava`). `parseArtifactName` re-derives the mangled label from the Maven coordinate by applying `rules_jvm_external`'s own normalisation rules:

- `groupId:artifactId` → `groupId_artifactId`
- `groupId:artifactId:packaging` → `groupId_artifactId` (packaging is dropped)
- `groupId:artifactId:packaging:classifier` → `groupId_artifactId_classifier` (classifier preserved, packaging still dropped)
- Then `.`, `-`, `$` are replaced with `_` to match Bazel's identifier rules.

This mirrors the logic in [`rules_jvm_external/private/rules/artifact.bzl`](https://github.com/bazel-contrib/rules_jvm_external/blob/master/private/rules/artifact.bzl) — if upstream changes its mangling, this function needs to track it.

### Why `maven` as the package manager name

`packageManagerName()` returns `"maven"` rather than something Bazel-specific. Snyk's vulnerability database is keyed by ecosystem, and JVM artifacts coming out of `rules_jvm_external` are ordinary Maven coordinates regardless of which build system pulled them in. Tagging the graph as `maven` lets the existing vulnerability matching pipeline work unchanged.

### Edge attributes

Only `deps`, `runtime_deps`, and `exports` are followed. Bazel rules expose many other label-typed attributes (`plugins`, `data`, `tags`, `srcs`, …) that are not JVM library dependencies in the classpath sense; pulling those into the graph would surface false-positive vulnerable paths.

## Go resolver (`go.go`)

### `go.mod`-driven version lookup

Go versions live in `go.mod`. We use `golang.org/x/mod/modfile` to parse it and `github.com/bazelbuild/bazel-gazelle/label.ImportPathToBazelRepoName` to compute the same Bazel repository name that `gazelle` / the `bzlmod` `go_deps` extension would generate for each `require`. The result is a `repo-name → PkgInfo` map (e.g. `com_github_spf13_cobra` → `github.com/spf13/cobra @ 1.8.0`).

`replace` directives are honoured when they point at another versioned module — the lookup key stays as the *original* require path (because that is still what gazelle uses to name the Bazel repo), but the value points at the replacement's module path and version. Path-only replaces (e.g. `replace foo => ../local/foo`) have no version and can't be turned into a scannable coordinate, so we fall through to the original require entry.

### Pseudo-version normalisation

Snyk's `gomodules` ecosystem doesn't store Go's semver-prefixed (`v1.2.3`) or pseudo-version (`v0.0.0-20230101000000-abc123def456`) strings verbatim. `normalizeVersion` strips the leading `v` from tagged versions and reduces pseudo-versions to `#<12-char-revision>`, matching the convention used elsewhere in the dep-graph pipeline.

### Sub-package resolution

Go's vulnerability data is keyed by *import path*, not module path — a CVE may apply to `github.com/foo/bar/internal/unsafe` but not to other packages in the same module. Bazel labels carry this information: an external Go target looks like `@com_github_foo_bar//internal/unsafe:unsafe`, where `internal/unsafe` is the in-module package path. `labelToPkgInfo` parses the label, looks up the module by repo name, and concatenates `module + "/" + pkg-path` to produce the final import path. Labels at the module root (`@com_github_foo_bar//:bar`) keep just the module path.

### bzlmod canonical labels

Under bzlmod, `cquery` reports canonical labels like `@@rules_go~~go_deps~com_github_spf13_cobra//cobra:cobra`. The leading `@@…~` / `+` segments encode module-extension provenance; only the trailing apparent-repo segment is what we need for the lookup. The resolver strips everything before the last `~` or `+` in the repo portion before consulting the map.

### Edge attributes

`rules_go` propagates dependencies via `deps` (regular library edges) and `embed` (same-package compilation units stitched together at build time). Both are followed; everything else is ignored.

## First-party and unknown targets

Both resolvers preserve unresolved labels as graph nodes with no version, rather than dropping them. This is deliberate:

- First-party Bazel targets (`//path/to:lib`) are legitimate intermediate nodes in the dep-graph.
- An unrecognised external repo could indicate a missing lockfile entry, a typo in `parseArtifactName`'s mangling rules, or a brand-new ruleset we haven't taught the resolver about. Keeping the node visible makes those cases triagable instead of silently lossy.

The downside is that "phantom" nodes without versions cannot be matched against the vuln database — they show up in the graph but contribute nothing to a scan. The expectation is that real ecosystem coordinates eventually appear *below* them as transitive children.

## Why `cquery` and not `query`

`bazel query` works on the unconfigured target graph and doesn't see select-resolved or platform-conditional deps. `bazel cquery` works on the *configured* target graph, which is what actually gets built. For accurate vulnerability reporting we need the latter — e.g. an Android `cc_library` that selects between platform-specific deps via `select({})` should report whichever branch is active in the user's build configuration.

The trade-off: `cquery` requires the workspace to be loadable (toolchains resolved, repository rules fetchable). Workspaces that can't load will fail target discovery; a `query`-based fallback for partial graph extraction is something we may revisit if it becomes a recurring blocker.

## Integration tests

Integration tests live alongside the unit tests in this package and are gated behind environment variables so they don't run in the default `go test ./...` pass — they need a working `bazel` on `PATH` and (for the Android JVM fixture) `ANDROID_HOME` pointing at an SDK.

```sh
make test-bazel-jvm-integration   # BAZEL_JVM_INTEGRATION_TESTS=1
make test-bazel-go-integration    # BAZEL_GO_INTEGRATION_TESTS=1
```

Fixtures live under `pkg/ecosystems/testdata/fixtures/bazel/` they are working examples of Bazel projects.
