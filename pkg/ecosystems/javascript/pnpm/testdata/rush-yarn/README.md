# rush-yarn — Rush + yarn (out of scope; detect & skip)

A Rush monorepo configured with **`yarnVersion`** instead of `pnpmVersion`.

- **PRD mapping:** PR-7 (Rush + npm / yarn — detect and skip). Out of scope per *Out of scope* (pnpm-only).
- **Expected (post-Rush-support):** Snyk detects the Rush repo and **skips with a clear message** stating Rush is supported only with pnpm.
- **Today:** no Rush awareness.

This fixture exists to prove the skip-message path, not to scan.
