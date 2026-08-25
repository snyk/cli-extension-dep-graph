# .NET acceptance fixtures

Each directory is a scannable .NET project: an `obj/project.assets.json` and one golden dep graph
per target framework. `acceptance_test.go` runs the plugin over the directory and diffs the result
against the goldens.

Nothing here needs a .NET SDK. The resolver only reads restore output, so the assets files are
committed and the suite runs in the normal `test` job.

## Golden files

One per target framework, named `expected-<targetRuntime>.json` — always, including for a
single-framework project. The runtime is not part of the dep graph, so the filename is what pins
it: with a bare `expected.json`, a resolver reporting the raw `targets` key
(`.NETStandard,Version=v2.1`) instead of the moniker the project declared (`netstandard2.1`) would
leave every golden untouched.

Regenerate after an intentional parser change, then read the diff before committing it:

```
go test ./pkg/ecosystems/dotnet/nuget/... -run TestAcceptance -update
```

## The cases

| Case | What it pins down |
| --- | --- |
| `net8-no-dependencies` | No `projectFileDependencyGroups` at all — a root-only graph, not an error. |
| `net-multi-target` | One graph per framework, each resolving a different version of the same package. `net7.0/linux-x64` is written *before* `net7.0` so the exact-match preference is load-bearing. |
| `netcoreapp-long-moniker` | `project.frameworks` says `netcoreapp1.1`, `targets` says `.NETCoreApp,Version=v1.1`. Neither is a prefix of the other, so this exercises the sole-key fallback — which only applies because there is exactly one target. The multi-target case, where there is no safe guess, is a unit test (`TestProjectAssets_MatchTargetsKey`) because it produces no graph to golden. |
| `netstandard-remap` | `netstandard2.1` → `.NETStandard,Version=v2.1`, the one mapping derived rather than looked up. |
| `project-reference` | A `type: "project"` entry becomes an ordinary node, and its own dependency is shared with the root. |
| `pinned-and-case-insensitive` | Declared names differ in case from the `targets` keys; the resolved version wins over a lower declared minimum; a framework reference absent from `targets` is skipped rather than fatal. |
| `cycle-and-diamond` | A diamond yields one node with two parents; a cycle yields a `…:pruned` leaf; a `runtime.native.*` package is filtered out. |
| `sibling-order-decides-pruning` | `Top` declares `Zeta` before `Alpha`, and `Zeta` also depends on `Alpha`. In document order `Zeta → Alpha` is a real edge; walk the siblings in any other order and it becomes `Alpha@1.0.0:pruned` instead. This is the only fixture that fails if the resolver stops preserving document order — real NuGet output writes dependency keys already sorted, so no fixture taken from a real project can catch that regression. |

`net8-no-dependencies` is real restore output from `snyk/cli` (`test/fixtures/nuget-app`); the rest
are hand-written to stay small enough to read. Breadth over a real project is covered by
`testdata/parity/dotnet_6`, which diffs against `snyk-nuget-plugin`'s own output rather than a
snapshot of ours.
