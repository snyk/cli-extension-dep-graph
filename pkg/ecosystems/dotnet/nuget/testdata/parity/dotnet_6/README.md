# Parity fixture: dotnet_6

Two files describing the same project, from the two repositories that resolve it:

- `obj/project.assets.json` — restore output, copied from `snyk/cli`
  (`test/acceptance/workspaces/nuget-app-6/obj/project.assets.json`).
- `snyk-nuget-plugin.json` — the dep graph `snyk-nuget-plugin` produces from it, copied from
  `test/fixtures/dotnetcore/dotnet_6/expected_depgraph-v3.json` and unwrapped from its
  `{"depGraph": …}` envelope.

The golden was last regenerated upstream by `snyk-nuget-plugin` commit `02b88a4` ("fix: updated
pruning of v3 parser", #245, 2025-05-30), which is the change that last altered v3 pruning output.
`snyk/cli` pins `snyk-nuget-plugin` at `^4.5.1`. Record the upstream commit whenever this file is
refreshed: without it, a diff between the two resolvers cannot be attributed to either one.

`parity_test.go` resolves the assets file and asserts the two graphs are structurally identical.
The project is worth pinning because it is large enough to exercise the parts of the traversal a
small fixture cannot: 105 nodes, 68 packages, 37 pruned back-edges, and `targets` sections for both
`net6.0` and `net6.0/linux-x64`.

The one difference the test allows for is package **versions**, and it is a limitation rather than a
choice. `snyk-nuget-plugin` rewrites 97 of them from `PackageOverrides.txt`, which it reads out of
the host SDK at
`$(dirname sdkPath)/packs/Microsoft.NETCore.App.Ref/$(runtimeVersion)/data/PackageOverrides.txt`
after shelling out to `dotnet --info` and `dotnet --list-runtimes` — so `System.Runtime@4.3.0` is
reported as `System.Runtime@6.0.0`. That file is not in the repository being scanned and its
contents depend on which SDK happens to be installed, so there is no way to reproduce it without
invoking `dotnet`. Closing this gap means putting `dotnet` back in scope, which is the question
CMPA-714 exists to answer.

Node identities keep the resolved version in both implementations, which is why the node and edge
sets match exactly and only the package versions differ.

The directory is named `dotnet_6` on purpose: this resolver names the root component after the
project directory, so for this single-project fixture the name coincides with upstream's and the
comparison covers the root package too.

Note that the two do **not** agree in general, and this fixture cannot show it. Upstream's
`getRootName` uses `basename(root)` — the *scan root* — and `snyk/cli` passes the scan root for
every project, including under `--all-projects` (`get-multi-plugin-result.ts` calls
`getSinglePluginResult(root, …)` with the walk root, not the project directory). So upstream names
every .NET project in a solution after the repository directory, while this resolver names each one
after its own directory. Which behaviour we want is an open question on the PR: matching upstream
means colliding root names across a monorepo, and the per-directory name shipped in CMPA-694.

Refresh this fixture only alongside the upstream one, and re-read the diff: a change in the node or
edge sets means the parsers have diverged.
