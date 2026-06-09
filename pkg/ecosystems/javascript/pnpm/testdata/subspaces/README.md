# subspaces — Rush + pnpm subspaces (detect & warn; full scan out of scope)

A Rush monorepo with **subspaces enabled**. Per-subspace lockfiles live at
`common/config/subspaces/<name>/pnpm-lock.yaml`, and a monorepo-level
`common/config/rush/pnpm-lock.yaml` is **forbidden** when subspaces are on.

- **PRD mapping:** PR-6 (subspaces detection + warning). Full subspaces scanning is **out of scope** in v1.
- **Expected (post-Rush-support):** Snyk detects `common/config/rush/subspaces.json` (`subspacesEnabled: true`) and **warns clearly** that subspaces aren't fully scanned yet — it must **never silently return zero**.
- **Today:** silent zero — the v1 hardcoded `common/config/rush/` path finds no lockfile and scans nothing.

Note: the lockfile here is a representative pnpm v6 file showing the subspaces layout; it is not produced by `rush install` in this fixture. The detection/warn path keys off `subspaces.json`, not lockfile contents.
