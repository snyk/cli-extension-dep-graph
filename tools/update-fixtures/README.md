# Update Python Fixtures Tool

A development tool to automatically regenerate Python integration test fixtures to reflect current transitive dependencies.

Located in `tools/update-fixtures/` - this is a build/development tool rather than a production command.

## What it does

1. **Regenerates expected outputs** - Runs the actual Go plugin to generate fresh `expected_plugin*.json` files with resolved dependency graphs based on the current requirements.txt
2. **Preserves runtime metadata** - Keeps existing runtime version information to avoid unnecessary diffs
3. **Uses your local Python version** - Generates fixtures based on whatever Python version you have installed

## Usage

### Regenerate with current Python version

```bash
make update-python-fixtures
```

### Regenerate with a specific Python version

```bash
PYTHON_VERSION=3.10 make update-python-fixtures
```

### Regenerate for all Python versions (3.8, 3.9, 3.10, 3.14)

```bash
make update-python-fixtures-all
```

This will automatically switch between Python versions using pyenv and regenerate all fixtures for each version.

## How it works

1. **Detects your Python version** - Uses the currently installed Python (e.g., 3.14)
2. **Finds all fixtures** - Scans `pkg/ecosystems/testdata/fixtures/python/` for all fixture directories
3. **Discovers requirements files** - Finds all `requirements.txt` files in each fixture (including subdirectories)
4. **Generates dependency graphs** - Runs the actual `pip.Plugin` to resolve dependencies and build graphs
5. **Preserves runtime metadata** - Keeps existing runtime values to avoid unnecessary diffs
6. **Updates fixture files** - Writes to `expected_plugin.json` or `expected_plugin_X.Y.json` based on what exists

### Python Version Handling

- The script uses your **currently installed Python version**
- For fixtures with `expected_plugin.json` (no version suffix): assumes Python 3.14
- For fixtures with version-specific files (e.g., `expected_plugin_3.8.json`): updates only the file matching your Python version
- Warns if other version-specific files exist that need different Python versions

The Makefile commands handle Python version switching automatically using pyenv.

## Notes

- The tool requires `pip` to be available in your PATH
- The tool uses the current Python environment to resolve dependencies
- For version-specific fixtures, you may need to use `pyenv` or similar to switch Python versions
- The generated JSON is formatted with 2-space indentation to match existing fixtures
