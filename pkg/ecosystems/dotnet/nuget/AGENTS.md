# AGENTS.md — .NET (nuget) plugin

Scoped rules for the .NET/nuget ecosystem plugin. The repo-wide rules in the root [`AGENTS.md`](../../../../AGENTS.md) still apply.

## Hard rules

- **Project identity must set `Identity.TargetRuntime`** (the disambiguating field for multi-framework projects) and propagate it to workflow metadata. Construct identity through the constructor that requires the runtime so it cannot be silently dropped. See [`plugin.go`](plugin.go).

The repo-wide TS-plugin parity rule in the root `AGENTS.md` applies here too — the upstream reference is `snyk-nuget-plugin`.
