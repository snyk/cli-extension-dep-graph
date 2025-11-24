# Release Process

This document describes the automated release process for the `cli-extension-dep-graph` project.

## Overview

The project uses **Semantic Versioning** (semver) and automates releases using CircleCI and GoReleaser. Releases are triggered automatically when code is merged to the `main` branch.

The version bump is determined by the **Pull Request title**, which must follow the Conventional Commits format. A GitHub Action automatically validates PR titles when you create or edit a PR.

## How It Works

### 1. PR Title Convention

The release system uses **Pull Request titles** following the **Conventional Commits** format to determine version bumps:

- **`fix:`** or **`fix(scope):`** → Bumps **PATCH** version (e.g., 1.0.0 → 1.0.1)
- **`feat:`** or **`feat(scope):`** → Bumps **MINOR** version (e.g., 1.0.0 → 1.1.0)
- **`type!:`** (breaking change) → Bumps **MAJOR** version (e.g., 1.0.0 → 2.0.0)
- **`chore:`**, **`docs:`**, **`style:`**, **`refactor:`**, **`test:`**, **`ci:`** → **No release** created

### 2. PR Title Examples

When creating a Pull Request, use these title formats:

```
# Patch version bump (bug fixes)
fix: resolve null pointer exception in parser
fix(parser): handle edge case in dependency resolution

# Minor version bump (new features)
feat: add support for new dependency format
feat(python): add Python 3.13 support

# Major version bump (breaking changes)
# Use ! after type or type(scope) to indicate breaking changes
fix!: change return type of core API
feat(api)!: redesign authentication flow
refactor(parser)!: remove support for legacy format
chore!: drop support for Python 3.7

# No release (maintenance)
chore: update dependencies
docs: improve README documentation
test: add integration tests for edge cases
```

### 3. GitHub Action - PR Title Validation

When you create or edit a Pull Request:

1. A GitHub Action automatically validates the PR title against the Conventional Commits format
2. The action will:
   - ✅ Pass if the title follows the correct format (e.g., `feat:`, `fix:`, `fix!:`)
   - ❌ Fail if the title is invalid
3. The check must pass before the PR can be merged

### 4. CircleCI Workflow

When code is merged to `main` using **"Squash and merge"**, the following happens:

1. **Run Tests**: All tests (lint, unit tests, integration tests, security scans) must pass
2. **Determine Version**: The `version-bump.sh` script reads the commit subject (PR title) and determines the version bump
3. **Tag Release**: If a release is needed (not a chore), a git tag is created and pushed (e.g., `v1.2.3`)
4. **Build & Release**: GoReleaser creates:
   - GitHub Release with changelog
   - Source archives for Linux, macOS, and Windows
   - Checksums for verification

**Note:** Always use "Squash and merge" when merging PRs to ensure the PR title becomes the commit message.

### 5. Increasing the Major Version

To trigger a **major version bump**, add `!` after the type (or scope) in your PR title:

```
# Breaking change examples
PR Title: fix!: change API return type
PR Title: feat(api)!: redesign authentication flow
PR Title: refactor(parser)!: remove legacy format support
PR Title: chore!: drop support for Python 3.7
```

**Standard:** This follows the [Conventional Commits specification](https://www.conventionalcommits.org/) which uses `!` to indicate breaking changes in the commit subject line.

**Note:** The `BREAKING CHANGE:` footer in commit bodies is part of the Conventional Commits spec, but our PR title validation only checks the subject line. Use `!` in the PR title for automatic major version bumps.

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

### Required SSH Key

The CircleCI project must have an SSH key configured for pushing tags to GitHub:

1. Go to CircleCI → Project Settings → SSH Keys
2. Add a new SSH key with write access to the repository
3. The fingerprint is already configured in `.circleci/config.yml`:
   - `SHA256:w5lYpE8DMWxUdasN8yMbbFdiz6s50PPBJMkV0a1iyZ8`

**Note:** The SSH key must have push permissions to the `snyk/cli-extension-dep-graph` repository.

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
- Check if PR title starts with `chore:`, `docs:`, etc. (these skip releases)
- Verify all tests passed in CircleCI
- Check CircleCI logs for the "Determine Version" job
- Verify the PR title was correctly formatted

### Wrong version bump

**Problem**: Expected a minor bump but got a patch bump.

**Solutions**:
- Verify PR title follows convention: `feat:` for minor, `fix:` for patch, `type!:` for major
- Check the "Determine Version" job output in CircleCI to see the calculated version bump
- PR title must match the regex patterns in `version-bump.sh`
- Ensure the GitHub Action validation check passed on the PR

### Tag push fails with authentication error

**Problem**: Tag creation fails with permission denied or authentication error.

**Solutions**:
- Verify SSH key is configured in CircleCI project settings
- Ensure the fingerprint in `.circleci/config.yml` matches the key in CircleCI
- Check that the SSH key has push permissions to the repository
- Verify the SSH key hasn't been revoked or removed from GitHub

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
