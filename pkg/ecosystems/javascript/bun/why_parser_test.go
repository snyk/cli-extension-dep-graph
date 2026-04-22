package bun

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

func openFixture(t *testing.T, path string) *os.File {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)

	t.Cleanup(func() { f.Close() })

	return f
}

func parseFixture(t *testing.T, path string) (*whyOutput, error) {
	t.Helper()

	return parseWhyOutput(context.Background(), logger.Nop(), openFixture(t, path))
}

func TestParseWhyOutput_Simple(t *testing.T) {
	out, err := parseFixture(t, "testdata/simple/why_output.txt")
	require.NoError(t, err)

	// All resolved packages are in the graph.
	assert.Contains(t, out.Graph, "debug@4.4.3")
	assert.Contains(t, out.Graph, "ms@2.1.3")
	assert.Contains(t, out.Graph, "@types/bun@1.3.11")
	assert.Contains(t, out.Graph, "bun-types@1.3.11")
	assert.Contains(t, out.Graph, "@types/node@25.5.2")
	assert.Contains(t, out.Graph, "undici-types@7.18.2")

	// Root project should not appear as a node.
	for id := range out.Graph {
		assert.False(t, strings.HasPrefix(id, "my-app@"), "root project should not appear in Graph")
	}

	// Prod vs dev classification.
	assert.Contains(t, out.ProdDeps, "debug@4.4.3")
	assert.Contains(t, out.DevDeps, "@types/bun@1.3.11")

	// Reverse adjacency: debug depends on ms → ms's dependents include debug.
	assert.Contains(t, out.Graph["ms@2.1.3"], "debug@4.4.3")

	// Reverse adjacency: @types/bun depends on bun-types → bun-types's dependents include @types/bun.
	assert.Contains(t, out.Graph["bun-types@1.3.11"], "@types/bun@1.3.11")
}

func TestParseWhyOutput_Workspace(t *testing.T) {
	out, err := parseFixture(t, "testdata/workspace/why_output.txt")
	require.NoError(t, err)

	// Workspace packages are in the graph with their full workspace IDs.
	assert.Contains(t, out.Graph, "@workspace/logger@workspace:packages/logger")
	assert.Contains(t, out.Graph, "@workspace/utils@workspace:packages/utils")

	// Regular packages present.
	assert.Contains(t, out.Graph, "debug@4.4.3")
	assert.Contains(t, out.Graph, "axios@1.14.0")

	// Reverse adjacency: @workspace/logger depends on axios → axios's dependents include @workspace/logger.
	assert.Contains(t, out.Graph["axios@1.14.0"], "@workspace/logger@workspace:packages/logger")

	// Reverse adjacency: axios depends on follow-redirects → follow-redirects's dependents include axios.
	assert.Contains(t, out.Graph["follow-redirects@1.15.9"], "axios@1.14.0")
}

func TestParseWhyOutput_EmptyInput(t *testing.T) {
	out, err := parseWhyOutput(context.Background(), logger.Nop(), strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, out.Graph)
	assert.Empty(t, out.ProdDeps)
	assert.Empty(t, out.DevDeps)
}

func TestParseWhyOutput_SkipsRootProject(t *testing.T) {
	input := strings.NewReader("my-app@\n  └─ No dependents found\n\ndebug@4.4.3\n  └─ my-app (requires ^4.4.3)\n")

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)

	// Root project must not appear in the graph.
	for id := range out.Graph {
		assert.False(t, strings.HasPrefix(id, "my-app@"), "root project should not appear in Graph")
	}

	// debug is a prod dep of root.
	assert.Contains(t, out.Graph, "debug@4.4.3")
	assert.Contains(t, out.ProdDeps, "debug@4.4.3")
}

func TestParseWhyOutput_PeerDeps(t *testing.T) {
	input := strings.NewReader("typescript@5.9.3\n  └─ peer my-app (requires ^5)\n")

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)

	// typescript is a peer dep of root → treated as a prod dep.
	assert.Contains(t, out.Graph, "typescript@5.9.3")
	assert.Contains(t, out.ProdDeps, "typescript@5.9.3")

	// typescript has no versioned dependents (its only dependent is the root project).
	assert.Empty(t, out.Graph["typescript@5.9.3"])
}

func TestParseWhyOutput_WorkspaceVersionTruncation(t *testing.T) {
	// bun why truncates workspace versions in depth-1 lines:
	// the root entry uses the full "workspace:packages/b" version, but when
	// package b depends on package a, the depth-1 line under a lists the
	// dependent as "b@workspace" (without the path suffix).
	//
	// Crucially, bun outputs entries alphabetically, so a is processed before b.
	// The normalisation must therefore run as a post-pass once all canonical IDs
	// are known.
	input := strings.NewReader(
		// a appears first alphabetically; its dependent b is not yet in the graph.
		"a@workspace:packages/a\n" +
			"  └─ b@workspace (requires workspace:*)\n\n" +
			// b appears second; its root line adds it to the graph.
			"b@workspace:packages/b\n" +
			"  └─ root-app\n\n" +
			// ms depends on a (also truncated — appears after a's root line).
			"ms@2.1.3\n" +
			"  └─ a@workspace (requires ^2.0.0)\n",
	)

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)

	assert.Contains(t, out.Graph, "a@workspace:packages/a")
	assert.Contains(t, out.Graph, "b@workspace:packages/b")
	assert.Contains(t, out.Graph, "ms@2.1.3")

	// b depends on a → after normalisation, a's dependents include b (canonical form).
	assert.Contains(t, out.Graph["a@workspace:packages/a"], "b@workspace:packages/b",
		"b's truncated dependent reference to a should resolve to canonical version")

	// a depends on ms → ms's dependents include a (canonical form).
	assert.Contains(t, out.Graph["ms@2.1.3"], "a@workspace:packages/a",
		"a's truncated dependent reference should resolve to canonical version")
}

func TestParseWhyOutput_ScopedPackage(t *testing.T) {
	input := strings.NewReader("@types/node@25.5.2\n  └─ bun-types@1.3.11 (requires *)\n")

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)

	assert.Contains(t, out.Graph, "@types/node@25.5.2")

	// bun-types depends on @types/node → @types/node's dependents include bun-types.
	assert.Contains(t, out.Graph["@types/node@25.5.2"], "bun-types@1.3.11")
}

func TestParseWhyOutput_MultipleVersionsSamePackage(t *testing.T) {
	// When bun installs two versions of the same package (root declares ms@^2,
	// some-lib requires ms@^3), both appear as root lines in bun why output.
	// ms@2.0.0 is root-direct (only dependent is root, recorded in ProdDeps).
	// ms@3.0.0 is transitive (dependent is some-lib, recorded in Graph).
	// Both appear as distinct entries in out.Graph.
	input := strings.NewReader(
		"ms@2.0.0\n" +
			"  └─ my-app (requires ^2)\n\n" + // root dep — no version, caught by depth1RootRe
			"ms@3.0.0\n" +
			"  └─ some-lib@1.0.0 (requires ^3)\n\n" +
			"some-lib@1.0.0\n" +
			"  └─ my-app (requires ^1)\n",
	)

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)

	// Both versions are in the graph.
	assert.Contains(t, out.Graph, "ms@2.0.0")
	assert.Contains(t, out.Graph, "ms@3.0.0")

	// ms@2.0.0 is root-direct; ms@3.0.0 is transitive.
	assert.Contains(t, out.ProdDeps, "ms@2.0.0", "ms@2.0.0 is the root-declared version")
	assert.NotContains(t, out.ProdDeps, "ms@3.0.0", "ms@3.0.0 is transitive, not root-direct")

	// ms@3.0.0 has some-lib as a dependent (some-lib depends on ms@3.0.0).
	assert.Contains(t, out.Graph["ms@3.0.0"], "some-lib@1.0.0")

	// ms@2.0.0 has no versioned dependents.
	assert.Empty(t, out.Graph["ms@2.0.0"])
}

func TestParseWhyOutput_OptionalDeps(t *testing.T) {
	// bun why prefixes optional dependent lines with "optional ".
	// The parser must treat these identically to regular versioned dependents.
	input := strings.NewReader(
		"@parcel/watcher-darwin-arm64@2.5.1\n" +
			"  └─ optional @parcel/watcher@2.5.1 (requires 2.5.1)\n\n" +
			"@parcel/watcher@2.5.1\n" +
			"  └─ my-app (requires 2.5.1)\n",
	)

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)

	assert.Contains(t, out.Graph, "@parcel/watcher@2.5.1")
	assert.Contains(t, out.Graph, "@parcel/watcher-darwin-arm64@2.5.1")

	// @parcel/watcher optionally depends on @parcel/watcher-darwin-arm64
	// → darwin's dependents include watcher.
	assert.Contains(t, out.Graph["@parcel/watcher-darwin-arm64@2.5.1"], "@parcel/watcher@2.5.1")

	// @parcel/watcher is a root-direct prod dep.
	assert.Contains(t, out.ProdDeps, "@parcel/watcher@2.5.1")
}
