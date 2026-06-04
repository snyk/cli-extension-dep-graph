# Release Process

This document describes the automated release process for the `cli-extension-dep-graph` project.

## Overview

The project uses **Semantic Versioning** (semver) and automates releases using CircleCI and GoReleaser. Releases are triggered automatically when code is merged to the `main` branch.

The version bump is determined by the **Pull Request title**, which must follow the Conventional Commits format. A GitHub Action automatically validates PR titles when you create or edit a PR.

## How It Works

### 1. PR Title Convention

The release system uses **Pull Request titles** following the **Conventional Commits** format to determine version bumps:

- **`feat:`** or **`feat(scope):`** → Bumps **MINOR** version (e.g., 2.0.0 → 2.1.0)
- **`type!:`** (breaking change marker) → Bumps **MINOR** version (treated the same as `feat:`; see "Major versions" below)
- **`fix:`**, **`perf:`**, **`revert:`**, **`refactor:`**, **`chore:`** (and their `(scope)` variants) → Bumps **PATCH** version (e.g., 2.0.0 → 2.0.1)
- **`docs:`**, **`style:`**, **`test:`**, **`ci:`**, **`build:`** → **No release** created

### 2. PR Title Examples

When creating a Pull Request, use these title formats:

```
# Patch version bump (bug fixes, refactors, chores)
fix: resolve null pointer exception in parser
fix(parser): handle edge case in dependency resolution
refactor(parser): simplify token stream handling
chore: update dependencies

# Minor version bump (new features, or "breaking" changes — see below)
feat: add support for new dependency format
feat(python): add Python 3.13 support
feat(api)!: redesign authentication flow

# No release (docs, formatting, CI, build config)
docs: improve README documentation
test: add integration tests for edge cases
ci: tighten lint config
```

### 3. Major versions are not supported

This module is committed to staying on its current major version (`v2`). New
major versions would require a Go module path change (e.g. `/v3`) and a
coordinated migration of every consumer, which we are not planning to do.

As a result, the `!` breaking-change marker in Conventional Commits (e.g.
`feat!:`, `refactor(api)!:`) is accepted but **does not** trigger a major
version bump — it is treated as a minor bump. The `BREAKING CHANGE:` footer
in commit bodies is likewise not interpreted by our release tooling (only the
subject line is read).

If you genuinely have a breaking change, prefer to split it so the public API
stays backwards-compatible, or raise it for discussion before merging.

### 4. GitHub Action - PR Title Validation

When you create or edit a Pull Request:

1. A GitHub Action automatically validates the PR title against the Conventional Commits format
2. The action will:
   - ✅ Pass if the title follows the correct format (e.g., `feat:`, `fix:`, `fix!:`)
   - ❌ Fail if the title is invalid
3. The check must pass before the PR can be merged

### 5. CircleCI Workflow

When code is merged to `main` using **"Squash and merge"**, the following happens:

1. **Run Tests**: All tests (lint, unit tests, integration tests, security scans) must pass
2. **Determine Version**: The `version-bump.sh` script reads the commit subject (PR title) and determines the version bump
3. **Tag Release**: If a release is needed (i.e. the PR title is not in the "no release" set), a git tag is created and pushed (e.g., `v2.1.0`) using CircleCI's built-in environment variables (`CIRCLE_PROJECT_USERNAME` and `CIRCLE_PROJECT_REPONAME`)
4. **Build & Release**: GoReleaser creates:
   - GitHub Release with changelog
   - Source archives for Linux, macOS, and Windows
   - Checksums for verification

**Note:** Always use "Squash and merge" when merging PRs to ensure the PR title becomes the commit message.

## Manual Release (Local Testing)

To test the release process locally:

```bash
# 1. Ensure you have GoReleaser installed
brew install goreleaser

# 2. Test the version bump script
./script/version-bump.sh

# 3. Test GoReleaser (snapshot mode, won't publish)
goreleaser release --snapshot --clean

# 4. Check the generated artifacts in ./dist/
ls -la ./dist/
```

## CircleCI Configuration

### Required Context Variable

The CircleCI `os-ecosystems` context must contain:

- **`GH_TOKEN`**: GitHub Personal Access Token or GitHub App token with `repo` permissions for pushing tags

### Context Setup

1. Go to CircleCI → Organization Settings → Contexts
2. Use existing context: `os-ecosystems`
3. Ensure the context has the environment variable:
   - **Name:** `GH_TOKEN`
   - **Value:** GitHub token with `repo` scope
   - Create token at: https://github.com/settings/tokens (if needed)

**Benefits:**
- ✅ No SSH key fingerprints to manage
- ✅ Easy to rotate - just update the context variable
- ✅ No risk of broken fingerprints after key rotation
- ✅ Works immediately without SSH key setup

## Release Artifacts

Each release includes:

- **Source archives**: `.tar.gz` and `.zip` formats
- **Checksums**: SHA256 checksums in `checksums.txt`
- **Changelog**: Auto-generated from commit messages
- **GitHub Release**: Published at https://github.com/snyk/cli-extension-dep-graph/releases

## Troubleshooting

### Release not created

**Problem**: Code was merged to `main` but no release was created.

**Solutions**:
- Check if PR title starts with `docs:`, `style:`, `test:`, `ci:`, or `build:` (these skip releases)
- Verify all tests passed in CircleCI
- Check CircleCI logs for the "Determine Version" job
- Verify the PR title was correctly formatted

### Wrong version bump

**Problem**: Expected a minor bump but got a patch bump.

**Solutions**:
- Verify PR title follows convention: `feat:` (or `type!:`) for minor; `fix:`/`perf:`/`revert:`/`refactor:`/`chore:` for patch
- Note: `!` breaking-change markers produce a **minor** bump, not a major one — see "Major versions are not supported"
- Check the "Determine Version" job output in CircleCI to see the calculated version bump
- PR title must match the regex patterns in `version-bump.sh`
- Ensure the GitHub Action validation check passed on the PR

### Tag push fails with authentication error

**Problem**: Tag creation fails with permission denied or authentication error.

**Solutions**:
- Verify `GH_TOKEN` is set in the CircleCI context: `os-ecosystems`
- Ensure the token has `repo` scope permissions
- Check that the token hasn't expired
- Verify the token is from a user/app with push permissions to the repository
- Test the token manually: `curl -H "Authorization: token $GH_TOKEN" https://api.github.com/user`

### Tag already exists

**Problem**: Tag creation fails because tag already exists.

**Solutions**:
- Delete the existing tag: `git tag -d v1.2.3 && git push origin :refs/tags/v1.2.3`
- Re-run the failed CircleCI workflow

## Best Practices

1. **Use Conventional Commits**: Always format PR titles using the conventional commit format for clear version bumps and changelogs
2. **Validate PR Title**: The GitHub Action will validate your PR title format automatically
3. **Squash and Merge**: When merging PRs, use "Squash and merge" - the PR title will become the commit message
4. **Update PR Title if Needed**: If the GitHub Action check fails, edit the PR title before merging
5. **Test Before Merging**: Ensure all tests pass before merging to `main`
6. **Review Changelog**: After release, review the auto-generated changelog for accuracy

## References

- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [GoReleaser Documentation](https://goreleaser.com/)
- [CircleCI Workflows](https://circleci.com/docs/workflows/)
