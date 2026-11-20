# .NET runtime-assembly version overrides Implementation Plan

> REQUIRED SUB-SKILL: Use the executing-plans skill to implement this plan task-by-task.

**Ticket:** [OSF-569](https://snyksec.atlassian.net/browse/OSF-569) (sub-task of OSF-526). Related: [CMPA-793](https://snyksec.atlassian.net/browse/CMPA-793), [CMPA-714](https://snyksec.atlassian.net/browse/CMPA-714).

**Goal:** For net5.0+ targets, the nuget plugin reports packages that the runtime supplies (`System.Net.Http`, `System.Runtime`, …) at the runtime version, as snyk-nuget-plugin's v3 parser does. That removes the `System.*` 4.x false positives the Dragonfly SCM flow raises today.

**Architecture:** Ship a static copy of `Microsoft.NETCore.App.Ref`'s `data/PackageOverrides.txt` with the plugin (`go:embed`). In `buildDepGraph`, for net5.0+ frameworks, rewrite a package's *version* (not its node ID) to the framework version under upstream's rule. A static table is enough: upstream only overrides entries whose assembly major is below 6, and those entries are the frozen .NET Core 1.x–3.x era packages, which every SDK since 6.0 lists identically. So the SDK dependence that blocked CMPA-714 only affects entries the rule never uses.

**Tech Stack:** Go, `embed`, `github.com/snyk/dep-graph/go/pkg/depgraph`, testify.

**PR Slices:**

1. Override runtime-supplied package versions for net5.0+ targets: SCM (Dragonfly) and CLI Go-path graphs for net6.0+ match snyk-nuget-plugin, and `parity_test.go` asserts exact versions.
2. Bump the module in snyk/os-sca-deps-discovery (separate repo, separate PR): Dragonfly SCM imports stop raising the false positives.

---

## Background the implementer needs

* Upstream rule, snyk/snyk-nuget-plugin:
  * `lib/nuget-parser/index.ts:189-262` (`getResultsWithoutPublish`) loads `PackageOverrides.txt` from the host SDK. It does so only when some framework is neither `netstandard*` nor `netcoreapp*`, and sets `overrideVersion` = the framework's NuGet.Frameworks version without its last component (`net6.0` → `"6.0.0"`).
  * `lib/nuget-parser/parsers/dotnet-core-v3-parser.ts:71-81`: `finalVersion = overrideVersion` when `resolvedVersion` major < 6 **and** the package is in the overrides **and** the override's major < 6. The node ID keeps the resolved version (`childID = name@resolvedVersion`). Only the package version changes.
* This repo already pins that difference as the one allowed divergence: `pkg/ecosystems/dotnet/nuget/parity_test.go:60-82` and `testdata/parity/dotnet_6/README.md`. 97 of the 105 nodes in that golden carry an overridden version.
* Measured in the OSF-526 parity run (2026-10-16, pre-prod): dotnet-6-fixture, dotnet-6-fixture-main-exploit (net6.0) and dotnet-simple-fixture (net7.0) each get `SNYK-DOTNET-SYSTEMNETHTTP-60045/60046/60047/60048/72439` and `SNYK-DOTNET-SYSTEMTEXTREGULAREXPRESSIONS-174708` with Dragonfly on, and none on legacy SCM, where the versions read 6.0.0 / 7.0.0.
* `mcr.microsoft.com/dotnet/sdk:10.0` (10.0.402) ships `/usr/share/dotnet/packs/Microsoft.NETCore.App.Ref/10.0.13/data/PackageOverrides.txt`, 272 lines of `Name|Version`, e.g. `System.Net.Http|4.3.4`, `System.AppContext|4.3.0`. Copy it from there; do not hand-write it.
* **Scope decision:** apply the rule to .NET 5+ (`netX.Y`, X ≥ 5, optional `-platform` suffix) only. Upstream also applies it to .NET Framework monikers (it excludes only `netstandard`/`netcoreapp`), which rewrites e.g. net461 `System.ValueTuple` 4.6.2 → 4.6.1 and net45 `System.Net.Requests` 4.3.0 → 4.5.0. Those assemblies are not part of .NET Framework in the way the overrides file describes. Reproducing that is out of scope and is listed as an open question on OSF-569. Record the divergence in `AGENTS.md` under "Sanctioned divergences" (Task 1.4).

## PR 1: Override runtime-supplied package versions for net5.0+ targets

**Value:** A net6.0+ project's graph reports `System.Net.Http@6.0.0` (etc.) instead of `@4.3.0`, matching snyk-nuget-plugin, so the `System.*` 4.x advisories no longer attach.
**Demo:** `go test ./pkg/ecosystems/dotnet/nuget/ -run 'TestParityWithSnykNugetPlugin|TestRuntimeOverrides'`. The parity test now asserts identical package versions.
**Merge safety:** Additive for net5.0+ graphs. netstandard, netcoreapp and .NET Framework graphs are byte-identical to today (covered by existing tests). Consumers pick it up only when they bump the module.
**Out of scope:** .NET Framework overrides; `Microsoft.AspNetCore.App.Ref` overrides (upstream does not read them either); the os-sca-deps-discovery bump.

### Task 1.1: Vendor the overrides table

**Files:**

- Create: `pkg/ecosystems/dotnet/nuget/runtimeoverrides/PackageOverrides.txt` (copied verbatim from the SDK 10.0.402 image, path above)
- Create: `pkg/ecosystems/dotnet/nuget/runtimeoverrides/README.md`: source image, SDK and runtime version, and why a static copy is safe (the threshold argument from Architecture)
- Create: `pkg/ecosystems/dotnet/nuget/overrides.go` (`//go:embed`, parse into `map[string]string` keyed by lower-cased name)
- Test: `pkg/ecosystems/dotnet/nuget/overrides_test.go`

**Step 1: Write the failing test**

```go
func TestRuntimeOverridesTableIsLoaded(t *testing.T) {
	v, ok := runtimeOverrides()["system.net.http"]
	require.True(t, ok, "System.Net.Http is a runtime-supplied package")
	assert.Equal(t, "4.3.4", v)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/ecosystems/dotnet/nuget/ -run TestRuntimeOverrides`
Expected: FAIL (undefined: `runtimeOverrides`)

**Step 3: Write minimal implementation**

`runtimeOverrides()` parses the embedded file once (`sync.OnceValue`). Split lines on `|`, trim `\r` and spaces (upstream trims a trailing CR), skip blank lines, and lower-case the key, because the plugin looks packages up lower-cased (`depgraph.go:147`).

**Step 4–6:** `make test && make lint`, expected ALL PASS. Refactor on green.

**Step 7: Commit**

Stage the new files and commit using the making-commits skill.
Message: `feat: vendor the .NET runtime PackageOverrides table [OSF-569]`

### Task 1.2: Decide which frameworks are overridden, and to what

**Files:**

- Modify: `pkg/ecosystems/dotnet/nuget/overrides.go`
- Test: `pkg/ecosystems/dotnet/nuget/overrides_test.go`

**Step 1: Write the failing test** (table-driven): `runtimeOverrideVersion(moniker) (string, bool)`:

| moniker | want |
|---|---|
| `net6.0` | `"6.0.0", true` |
| `net7.0` | `"7.0.0", true` |
| `net8.0-windows` | `"8.0.0", true` |
| `net10.0` | `"10.0.0", true` |
| `net5.0` | `"5.0.0", true` |
| `netcoreapp3.1`, `netstandard2.0`, `net48`, `net461`, `net45`, `v4.6.1`, `""` | `"", false` |

Also accept the long form the assets file can use as a targets key (`.NETCoreApp,Version=v6.0` → `"6.0.0", true`), because `buildDepGraph` receives a targets key, not always the alias. Check which form `matchTargetsKey` (`assets.go:359`) returns for the parity fixture, and test both.

**Step 2–6:** Run the test (FAIL), implement with one anchored regexp per form, then `make test && make lint`.

**Step 7: Commit**

Message: `feat: pick the runtime version net5.0+ packages are overridden to [OSF-569]`

### Task 1.3: Apply the override in the graph

**Files:**

- Modify: `pkg/ecosystems/dotnet/nuget/depgraph.go:14-66` (`buildDepGraph`: compute the override version once from `targetsKey`), `:118-175` (`graphBuilder` gets the override version; `addChildren` uses it for `PkgInfo.Version` only)
- Modify: the comment at `depgraph.go:18-21`: replace "minus the runtime-assembly version overrides…" with a pointer to `overrides.go` and OSF-569
- Test: `pkg/ecosystems/dotnet/nuget/depgraph_test.go`, `pkg/ecosystems/dotnet/nuget/parity_test.go:60-82`

**Step 1: Write the failing test**

In `depgraph_test.go`, take a minimal net6.0 assets fixture with `System.Runtime 4.3.0` and `Newtonsoft.Json 13.0.1`. Assert:

* the node `System.Runtime@4.3.0` exists, and its pkg is `System.Runtime@6.0.0` (node ID keeps the resolved version, as upstream);
* `Newtonsoft.Json@13.0.1` is unchanged (not in the table);
* the same fixture under `netstandard2.0` keeps `System.Runtime@4.3.0` as its pkg.

Then tighten `parity_test.go`:

* replace the "package versions are allowed to differ" block (`:60-73`) with `assert.Equal(t, packageIDs(&theirs), packageIDs(mine))`, i.e. names **and** versions;
* replace the loop at `:75-82` (which asserts node ID == pkg ID) with an assertion that the node/pkg pairs equal upstream's.

**Step 2: Run tests to verify they fail**

Run: `go test ./pkg/ecosystems/dotnet/nuget/ -run 'TestParityWithSnykNugetPlugin|TestBuildDepGraph'`
Expected: FAIL (versions differ on 97 nodes)

**Step 3: Write minimal implementation**

Thread `overrideVersion` (empty when the framework is out of scope) into `graphBuilder`. In `addChildren`, keep `childNodeID := pkgNodeID(pkg.name, pkg.version)`, but build `info` with the overridden version when all three hold:

* `overrideVersion != ""`,
* `major(pkg.version) < 6`,
* the table has `strings.ToLower(pkg.name)` with major < 6.

Apply it to the pruned node's `info` too, as upstream does.

Use the dep-graph builder's API to add a node whose ID differs from its pkg ID. `AddNode(nodeID, info)` already takes both. Verify that `Build()` dedupes `pkgs` by `name@version`, so two node IDs that map to the same overridden pkg produce one pkg entry (upstream's graphlib does).

**Step 4: Run ALL tests to verify they pass**

Run: `make test`
Expected: ALL PASS, including `TestParityWithSnykNugetPlugin` with exact versions. If any of the 97 overridden versions still differs, compare against upstream's golden before changing the rule: the golden was produced by a specific SDK (see `testdata/parity/dotnet_6/README.md`).

**Step 5: Refactor.** Keep the override decision in `overrides.go` and out of the traversal. `addChildren` should call one helper, e.g. `g.reportedVersion(pkg)`.

**Step 6:** `make test && make lint`, expected ALL PASS.

**Step 7: Commit**

Message: `fix: report runtime-supplied packages at the runtime version on net5.0+ [OSF-569]`

### Task 1.4: Record the remaining divergence

**Files:**

- Modify: `pkg/ecosystems/dotnet/nuget/AGENTS.md` ("Sanctioned divergences from `snyk-nuget-plugin`")
- Modify: `pkg/ecosystems/dotnet/nuget/testdata/parity/dotnet_6/README.md` (the "one difference the test allows for" paragraph is no longer true)

Add one bullet: runtime overrides apply to .NET 5+ only, and .NET Framework monikers are not overridden, unlike upstream. Link OSF-569 and CMPA-793. Update the README so that it says the parity test now asserts versions too.

Commit message: `docs: record the .NET Framework override divergence [OSF-569]`

### Task 1.5: Open the PR

Use the open-pr skill. Link OSF-569 and CMPA-793, and note that consumers need a module bump (PR 2).

## PR 2 (snyk/os-sca-deps-discovery): pick up the fix

**Value:** Dragonfly SCM imports of net6.0+ projects stop raising the `System.*` 4.x false positives.
**Demo:** Re-import snyk-fixtures/dotnet-6-fixture into pre-prod org `os-dfly-rollout`. `dotnet_6.csproj` shows `System.Net.Http@6.0.0` and none of `SNYK-DOTNET-SYSTEMNETHTTP-60045/60046/60047/60048/72439` or `SNYK-DOTNET-SYSTEMTEXTREGULAREXPRESSIONS-174708`, the same as `os-dfly-rollout-legacy`.
**Merge safety:** Dependency bump only.

### Task 2.1: Bump `github.com/snyk/cli-extension-dep-graph/v2`

In snyk/os-sca-deps-discovery, run `go get github.com/snyk/cli-extension-dep-graph/v2@<release with PR 1>`, `go mod tidy`, then `go test ./...` and `make lint`. Commit `build: bump cli-extension-dep-graph for .NET runtime overrides [OSF-569]` and open the PR with the open-pr skill.

### Task 2.2: Check the CLI consumer

snyk/cli also embeds this extension. Tell the CLI team that the Go .NET path changes on the next bump: it gets closer to `cliDotnetRuntimeResolution`, not further away. No code change is expected there.
