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
- **`type!:`** - Breaking changes (bumps **MAJOR** version: 1.0.0 → 2.0.0)
- **`chore:`**, **`docs:`**, **`style:`**, **`refactor:`**, **`test:`**, **`ci:`** - No release created

### Examples

```bash
# Patch release
fix: resolve memory leak in dependency parser
fix(parser): handle edge case in requirements file

# Minor release
feat: add support for Python 3.13
feat(python): add environment marker support

# Major release (breaking changes - use ! indicator)
fix!: change API return type
feat(api)!: redesign core interface
refactor!: remove deprecated parser
chore!: drop support for Python 3.7

# No release
chore: update CI configuration
docs: improve README documentation
```

### Pull Request Guidelines

When creating a pull request:
1. **Use a descriptive title** following the conventional commit format (examples above)
2. **Check the GitHub Action** - A check will automatically validate your PR title format
   - ✅ Check passes if title is valid (e.g., `feat:`, `fix:`, `fix!:`)
   - ❌ Check fails if title format is invalid
3. **Edit the title if needed** - If validation fails, edit your PR title before merging
4. **Use "Squash and merge"** - The PR title will become the commit message
5. **Ensure all tests pass** before merging
6. **Releases are automatic** - When merged to `main`, CircleCI will automatically create a release

For more details, see the [Release Process Documentation](docs/RELEASE.md).
