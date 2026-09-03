# AGENTS.md — bun plugin

Scoped rules for the bun ecosystem plugin. The repo-wide rules in the root [`AGENTS.md`](../../../../AGENTS.md) still apply.

## Hard rules

- **When shelling out to bun, pass `--no-env-file` to `bun why`** — bun otherwise loads the repo's `.env`, which can change resolution — and require bun ≥ 1.2.19 (the first version supporting `bun why '*'`). See [`executor.go`](executor.go).
