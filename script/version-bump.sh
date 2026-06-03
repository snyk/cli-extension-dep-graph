#!/bin/bash
set -e

# Get latest tag or default to v0.0.0
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
VERSION=${LATEST_TAG#v}

# Parse version components
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

# Get PR title (commit subject line)
PR_TITLE=$(git log -1 --pretty=%s)
echo "PR title: $PR_TITLE"

# Determine version bump based on PR title
if [[ "$PR_TITLE" =~ ^[a-z]+(\(.*\))?!: ]]; then
    # Breaking change indicator with ! (e.g., fix!:, feat(api)!:)
    BUMP_TYPE="major"
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
elif [[ "$PR_TITLE" =~ ^feat(\(.*\))?:|^feature: ]]; then
    BUMP_TYPE="minor"
    MINOR=$((MINOR + 1))
    PATCH=0
elif [[ "$PR_TITLE" =~ ^(fix|perf|revert|refactor|chore)(\(.*\))?: ]]; then
    BUMP_TYPE="patch"
    PATCH=$((PATCH + 1))
elif [[ "$PR_TITLE" =~ ^(docs|style|test|ci|build)(\(.*\))?: ]]; then
    BUMP_TYPE="none"
else
    echo "Warning: No recognized commit type, defaulting to NONE (no release)"
    echo "PR title should follow Conventional Commits format (validated by GitHub Action)"
    BUMP_TYPE="none"
fi

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
NEW_TAG="v${NEW_VERSION}"

echo "Bump type: $BUMP_TYPE ($LATEST_TAG → $NEW_TAG)"

# Guardrail: enforce Go Semantic Import Versioning when tagging v2+.
#
# Go modules require that any module at major version >= 2 carries the major
# version as a /vN suffix on the module path (e.g. module .../v2). Without
# this, `go get` cannot resolve v2+ tags and consumers see resolution errors.
# See: https://go.dev/ref/mod#major-version-suffixes
#
# This guardrail compares the major version in the upcoming tag against the
# /vN suffix in go.mod and aborts the release if they disagree.
if [ "$BUMP_TYPE" != "none" ]; then
    GO_MOD_PATH="$(dirname "$0")/../go.mod"
    if [ ! -f "$GO_MOD_PATH" ]; then
        echo "Error: cannot find go.mod at $GO_MOD_PATH" >&2
        exit 1
    fi

    MODULE_LINE=$(awk '/^module / {print $2; exit}' "$GO_MOD_PATH")
    if [ -z "$MODULE_LINE" ]; then
        echo "Error: could not parse module path from $GO_MOD_PATH" >&2
        exit 1
    fi

    # Extract trailing /vN suffix (if any) from the module path.
    if [[ "$MODULE_LINE" =~ /v([0-9]+)$ ]]; then
        MODULE_MAJOR="${BASH_REMATCH[1]}"
    else
        MODULE_MAJOR=1  # v0 and v1 both use no suffix
    fi

    # Tag major 0 and 1 both correspond to a module path with no /vN suffix.
    if [ "$MAJOR" -le 1 ]; then
        EXPECTED_MODULE_MAJOR=1
    else
        EXPECTED_MODULE_MAJOR="$MAJOR"
    fi

    if [ "$MODULE_MAJOR" != "$EXPECTED_MODULE_MAJOR" ]; then
        echo "Error: Go Semantic Import Versioning violation." >&2
        echo "  Upcoming tag:  $NEW_TAG (major=$MAJOR)" >&2
        echo "  Module path:   $MODULE_LINE" >&2
        if [ "$MAJOR" -le 1 ]; then
            echo "  Expected module path to have no /vN suffix." >&2
        else
            echo "  Expected module path to end with /v$MAJOR." >&2
        fi
        echo "" >&2
        echo "Before releasing $NEW_TAG, update the module path in go.mod and" >&2
        echo "rewrite all internal imports to match. See:" >&2
        echo "  https://go.dev/ref/mod#major-version-suffixes" >&2
        exit 1
    fi
fi

# Export for CircleCI (only if BASH_ENV is set)
if [ -n "$BASH_ENV" ]; then
    echo "export BUMP_TYPE=$BUMP_TYPE" >> "$BASH_ENV"
    echo "export NEW_VERSION=$NEW_VERSION" >> "$BASH_ENV"
    echo "export NEW_TAG=$NEW_TAG" >> "$BASH_ENV"
    echo "export PREVIOUS_TAG=$LATEST_TAG" >> "$BASH_ENV"
    # Safely export PR title (handles spaces and special characters)
    printf 'export PR_TITLE=%q\n' "$PR_TITLE" >> "$BASH_ENV"
fi
