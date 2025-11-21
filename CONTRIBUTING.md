# Contributing

This repo is intended for internal (Snyk) contributions only at this time.

Please [reach our support](SUPPORT.md) to give any feedback.

## Commit Message Convention

This project uses **Conventional Commits** for automated versioning and releases. Please follow this format when committing or creating pull requests:

### Format
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types and Their Effect on Versioning

- **`fix:`** - Bug fixes (bumps **PATCH** version: 1.0.0 → 1.0.1)
- **`feat:`** - New features (bumps **MINOR** version: 1.0.0 → 1.1.0)
- **`[major]`** or **`major:`** - Breaking changes (bumps **MAJOR** version: 1.0.0 → 2.0.0)
- **`chore:`**, **`docs:`**, **`style:`**, **`refactor:`**, **`test:`**, **`ci:`** - No release created

### Examples

```bash
# Patch release
fix: resolve memory leak in dependency parser

# Minor release
feat: add support for Python 3.13

# Major release (option 1)
[major] redesign API interface

# Major release (option 2)
major: remove deprecated functions

# No release
chore: update CI configuration
```

### Pull Request Guidelines

When creating a pull request:
1. **Use a descriptive title** following the conventional commit format (examples above)
2. **Check the GitHub Action** - A bot will automatically validate your PR title and post a comment showing:
   - Whether the title is valid ✅ or invalid ❌
   - The version bump type (MAJOR, MINOR, PATCH, or NO RELEASE)
3. **Edit the title if needed** - If validation fails or shows the wrong version bump, edit your PR title
4. **Use "Squash and merge"** - The PR title will become the commit message
5. **Ensure all tests pass** before merging
6. **Releases are automatic** - When merged to `main`, CircleCI will automatically create a release

For more details, see the [Release Process Documentation](docs/RELEASE.md).
