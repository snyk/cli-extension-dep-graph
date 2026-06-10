# simple-vulnerable-workspace — Rush + pnpm baseline (the easy case)

The canonical Rush + pnpm monorepo: two projects sharing one committed lockfile, with known-vulnerable dependencies. This is the easy case to work with.

- **Layout:** `apps/app-a` (depends on `lodash@4.17.4` and on `@rush-fix/lib-b` via `workspace:*`) + `libs/lib-b` (depends on `minimatch@3.0.0`). Shared lockfile committed at `common/config/rush/pnpm-lock.yaml`. No `common/temp/` and no root `pnpm-workspace.yaml` — i.e. a fresh SCM clone, exactly as the PRD describes.
- **PRD mapping:** PR-1–PR-5 / JTBD "scan an entire Rush + pnpm monorepo".
- **Expected (post-Rush-support):** `snyk test --all-projects` produces **one dep graph per Rush project** from the shared lockfile (no `rush install` needed) and reports the lodash + minimatch vulnerabilities.
- **Today (verified, current CLI 1.1304.0):** the gap reproduces exactly —
  - `snyk test` → `No supported files found (SNYK-CLI-0008)`.
  - `snyk test --all-projects` → finds `common/config/rush/pnpm-lock.yaml` but errors *"Could not find package.json at common/config/rush/package.json"* (the shared-deep-lockfile / no-sibling-package.json gap), and the per-project `package.json`s scan manifest-only.

To regenerate the lockfile: `rush update` (Rush 5.175.1, pnpm 8.15.8).
