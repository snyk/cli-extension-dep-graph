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
if [[ "$PR_TITLE" =~ ^\[major\]|^major: ]]; then
    BUMP_TYPE="major"
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
elif [[ "$PR_TITLE" =~ ^feat(\(.*\))?:|^feature: ]]; then
    BUMP_TYPE="minor"
    MINOR=$((MINOR + 1))
    PATCH=0
elif [[ "$PR_TITLE" =~ ^(fix|perf|revert)(\(.*\))?: ]]; then
    BUMP_TYPE="patch"
    PATCH=$((PATCH + 1))
elif [[ "$PR_TITLE" =~ ^(chore|docs|style|refactor|test|ci|build)(\(.*\))?: ]]; then
    BUMP_TYPE="none"
else
    echo "Warning: No recognized commit type, defaulting to PATCH"
    BUMP_TYPE="patch"
    PATCH=$((PATCH + 1))
fi

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
NEW_TAG="v${NEW_VERSION}"

echo "Bump type: $BUMP_TYPE ($LATEST_TAG → $NEW_TAG)"

# Export for CircleCI (only if BASH_ENV is set)
if [ -n "$BASH_ENV" ]; then
    echo "export BUMP_TYPE=$BUMP_TYPE" >> $BASH_ENV
    echo "export NEW_VERSION=$NEW_VERSION" >> $BASH_ENV
    echo "export NEW_TAG=$NEW_TAG" >> $BASH_ENV
    echo "export PREVIOUS_TAG=$LATEST_TAG" >> $BASH_ENV
fi
