# rush-npm — Rush + npm (out of scope; detect & skip)

A Rush monorepo configured with **`npmVersion`** instead of `pnpmVersion`.

- **PRD mapping:** PR-7 (Rush + npm / yarn — detect and skip). Out of scope per *Out of scope* (pnpm-only).
- **Expected (post-Rush-support):** Snyk detects `rush.json` with `npmVersion`, recognizes it as a Rush repo, and **skips with a clear, actionable message** — not a silent zero, not a crash.
- **Today:** no Rush awareness at all (`rush.json` isn't in the detectable-files list).

This fixture exists to prove the skip-message path, not to scan.
