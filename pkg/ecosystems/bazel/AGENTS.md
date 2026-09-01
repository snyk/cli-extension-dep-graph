# AGENTS.md — bazel plugin

Scoped rules for the bazel ecosystem plugin. The repo-wide rules in the root [`AGENTS.md`](../../../AGENTS.md) still apply.

## Hard rules

- **Use `bazel query` for target discovery but keep `bazel cquery` for dependency resolution.** `query` and `cquery` return the same target set in the loading phase, so target discovery uses the cheaper `query`; but only `cquery` (the analysis phase) resolves `select()` / platform-conditional deps, which dependency/edge resolution needs for accurate graphs (`go.go`, `jvm.go`). See [`query.go`](query.go) and the "Why `cquery` and not `query`" section of [`README.md`](README.md) (see #224).
