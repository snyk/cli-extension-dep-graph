# `/scripts`

Scripts to perform various build, install, analysis, etc operations.

These scripts keep the root level Makefile small and simple.

## Available Scripts

### `lint.sh`
Runs linting checks on the codebase using golangci-lint.

### `version-bump.sh`
Reads the commit subject (PR title) and determines the semantic version bump. Used by CircleCI for automated releases.

**Usage:**
```bash
./script/version-bump.sh
```

**Supported formats:**
- `fix:`, `perf:`, `revert:` → PATCH bump
- `feat:`, `feature:` → MINOR bump
- `[major]`, `major:` → MAJOR bump
- `chore:`, `docs:`, `test:`, `ci:`, `style:`, `refactor:`, `build:` → No release

Requires "Squash and merge" to ensure PR title becomes the commit message.