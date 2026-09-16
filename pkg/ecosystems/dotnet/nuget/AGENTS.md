# AGENTS.md — .NET (nuget) plugin

Scoped rules for the .NET/nuget ecosystem plugin. The repo-wide rules in the root [`AGENTS.md`](../../../../AGENTS.md) still apply.

## Hard rules

- **Project identity must set `Identity.TargetRuntime`** (the disambiguating field for multi-framework projects) and propagate it to workflow metadata. Construct identity through the constructor that requires the runtime so it cannot be silently dropped. See [`plugin.go`](plugin.go).

The repo-wide TS-plugin parity rule in the root `AGENTS.md` applies here too — the upstream reference is `snyk-nuget-plugin`.

## Sanctioned divergences from `snyk-nuget-plugin`

- **Build tooling the SDK injected is left out of the graph.** A reference is dropped only when NuGet flagged it `autoReferenced` in `project.assets.json` *and* the package it resolved to carries `build` assets with no `compile` or `runtime` ones. That is `Microsoft.DotNet.ILCompiler` and `Microsoft.NET.ILLink.Tasks`, whose versions come from whichever SDK ran the restore, so reporting them moves a graph that nobody changed. Upstream reports them; do not restore parity here without a new decision.
- **The flag alone is not the test.** `NETStandard.Library` and `Microsoft.NETFramework.ReferenceAssemblies` are `autoReferenced` too and must stay in the graph. Their versions are fixed by the target framework, not the SDK. See `sdkInjected` and `buildOnly` in [`assets.go`](assets.go), and mind the `_._` placeholder noted there.
