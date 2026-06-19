# rush-subspaces-disabled — subspaces.json present but turned off

Same layout as `simple-vulnerable-workspace` (two projects sharing one committed
lockfile at `common/config/rush/pnpm-lock.yaml`), but this repo *also* commits
`common/config/rush/subspaces.json` with `"subspacesEnabled": false`.

Rush ships a `subspaces.json` whenever the feature has ever been touched in
config, and only honours it when `subspacesEnabled` is `true`. With the flag
off, the monorepo-level lockfile is still the single source of truth, so the
repo is fully scannable.

- **Layout:** `apps/app-a` (`lodash@4.17.4` + `@rush-fix/lib-b` via
  `workspace:*`) + `libs/lib-b` (`minimatch@3.0.0`).
- **Expected:** scanned exactly like `simple-vulnerable-workspace` — one dep
  graph per Rush project (`@rush-fix/app-a`, `@rush-fix/lib-b`) from the shared
  lockfile.
- **Regression guard:** the earlier file-exists check skipped this repo (false
  `errRushSubspaces`). The fix parses `subspacesEnabled` and only skips when it
  is genuinely `true`, so this fixture must produce results, not an empty scan.
  Covered by `TestRushPnpm_SubspacesDisabledIsScanned`.

To regenerate the lockfile: `rush update` (Rush 5.175.1, pnpm 8.15.8).
