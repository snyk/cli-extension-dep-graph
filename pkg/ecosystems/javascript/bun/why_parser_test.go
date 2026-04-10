package bun

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openFixture(t *testing.T, path string) *os.File {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)

	t.Cleanup(func() { f.Close() })

	return f
}

func TestParseWhyOutput_Simple(t *testing.T) {
	graph, err := parseWhyOutput(openFixture(t, "testdata/simple/why_output.txt"))
	require.NoError(t, err)

	// All resolved packages should be present.
	assert.Equal(t, pkgVersion("4.4.3"), graph.Packages["debug"])
	assert.Equal(t, pkgVersion("2.1.3"), graph.Packages["ms"])
	assert.Equal(t, pkgVersion("1.3.11"), graph.Packages["@types/bun"])
	assert.Equal(t, pkgVersion("1.3.11"), graph.Packages["bun-types"])
	assert.Equal(t, pkgVersion("25.5.2"), graph.Packages["@types/node"])
	assert.Equal(t, pkgVersion("7.18.2"), graph.Packages["undici-types"])

	// Root project should not appear as a package.
	_, hasRoot := graph.Packages["my-app"]
	assert.False(t, hasRoot)

	// Forward adjacency: debug@4.4.3 depends on ms@2.1.3.
	debugDeps := graph.Dependencies[pkg{Name: "debug", Version: "4.4.3"}]
	assert.Contains(t, debugDeps, pkg{Name: "ms", Version: "2.1.3"})

	// Forward adjacency: @types/bun depends on bun-types.
	typesBunDeps := graph.Dependencies[pkg{Name: "@types/bun", Version: "1.3.11"}]
	assert.Contains(t, typesBunDeps, pkg{Name: "bun-types", Version: "1.3.11"})
}

func TestParseWhyOutput_Workspace(t *testing.T) {
	graph, err := parseWhyOutput(openFixture(t, "testdata/workspace/why_output.txt"))
	require.NoError(t, err)

	// Workspace packages should be in Packages with their workspace version.
	assert.Equal(t, pkgVersion("workspace:packages/logger"), graph.Packages["@workspace/logger"])
	assert.Equal(t, pkgVersion("workspace:packages/utils"), graph.Packages["@workspace/utils"])

	// Regular packages present.
	assert.Equal(t, pkgVersion("4.4.3"), graph.Packages["debug"])
	assert.Equal(t, pkgVersion("1.14.0"), graph.Packages["axios"])

	// Forward adjacency: @workspace/logger depends on axios.
	loggerDeps := graph.Dependencies[pkg{Name: "@workspace/logger", Version: "workspace:packages/logger"}]
	assert.Contains(t, loggerDeps, pkg{Name: "axios", Version: "1.14.0"})

	// Forward adjacency: axios depends on follow-redirects.
	axiosDeps := graph.Dependencies[pkg{Name: "axios", Version: "1.14.0"}]
	assert.Contains(t, axiosDeps, pkg{Name: "follow-redirects", Version: "1.15.9"})
}

func TestParseWhyOutput_EmptyInput(t *testing.T) {
	graph, err := parseWhyOutput(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, graph.Packages)
	assert.Empty(t, graph.Dependencies)
}

func TestParseWhyOutput_SkipsRootProject(t *testing.T) {
	input := strings.NewReader("my-app@\n  └─ No dependents found\n\ndebug@4.4.3\n  └─ my-app (requires ^4.4.3)\n")

	graph, err := parseWhyOutput(input)
	require.NoError(t, err)

	_, hasRoot := graph.Packages["my-app"]
	assert.False(t, hasRoot, "root project should not appear in Packages")
	assert.NotZero(t, graph.Packages["debug"])
}

func TestParseWhyOutput_PeerDeps(t *testing.T) {
	input := strings.NewReader("typescript@5.9.3\n  └─ peer my-app (requires ^5)\n")

	graph, err := parseWhyOutput(input)
	require.NoError(t, err)

	// typescript is a peer dep of root; root doesn't appear in Packages.
	assert.Equal(t, pkgVersion("5.9.3"), graph.Packages["typescript"])
	// No forward edges for typescript (its only dependent is root, which we skip).
	_, hasForward := graph.Dependencies[pkg{Name: "typescript", Version: "5.9.3"}]
	assert.False(t, hasForward)
}

func TestParseWhyOutput_WorkspaceVersionTruncation(t *testing.T) {
	// bun why truncates workspace versions in depth-1 lines:
	// the root entry uses the full "workspace:packages/b" version, but when
	// package b depends on package a, the depth-1 line under a lists the
	// dependent as "b@workspace" (without the path suffix).
	//
	// Crucially, bun outputs entries alphabetically, so a is processed before b.
	// When we encounter "b@workspace" as a dependent under a, b's root line
	// has not yet been seen — the fix must therefore run as a post-pass during
	// inversion, once the full packages registry is available.
	input := strings.NewReader(
		// a appears first alphabetically; its dependent b is not yet in the registry.
		"a@workspace:packages/a\n" +
			"  └─ b@workspace (requires workspace:*)\n\n" +
			// b appears second; its root line adds it to the registry.
			"b@workspace:packages/b\n" +
			"  └─ root-app\n\n" +
			// ms depends on a (also truncated — appears after a's root line).
			"ms@2.1.3\n" +
			"  └─ a@workspace (requires ^2.0.0)\n",
	)

	graph, err := parseWhyOutput(input)
	require.NoError(t, err)

	assert.Equal(t, pkgVersion("workspace:packages/a"), graph.Packages["a"])
	assert.Equal(t, pkgVersion("workspace:packages/b"), graph.Packages["b"])
	assert.Equal(t, pkgVersion("2.1.3"), graph.Packages["ms"])

	// b depends on a (b@workspace resolved to b@workspace:packages/b).
	bDeps := graph.Dependencies[pkg{Name: "b", Version: "workspace:packages/b"}]
	assert.Contains(t, bDeps, pkg{Name: "a", Version: "workspace:packages/a"},
		"b's truncated dependent reference to a should resolve to canonical version")

	// a depends on ms (a@workspace resolved to a@workspace:packages/a).
	aDeps := graph.Dependencies[pkg{Name: "a", Version: "workspace:packages/a"}]
	assert.Contains(t, aDeps, pkg{Name: "ms", Version: "2.1.3"},
		"a's truncated dependent reference should resolve to canonical version")
}

func TestParseWhyOutput_ScopedPackage(t *testing.T) {
	input := strings.NewReader("@types/node@25.5.2\n  └─ bun-types@1.3.11 (requires *)\n")

	graph, err := parseWhyOutput(input)
	require.NoError(t, err)

	assert.Equal(t, pkgVersion("25.5.2"), graph.Packages["@types/node"])

	// Forward adjacency: bun-types depends on @types/node.
	deps := graph.Dependencies[pkg{Name: "bun-types", Version: "1.3.11"}]
	assert.Contains(t, deps, pkg{Name: "@types/node", Version: "25.5.2"})
}

func TestParseWhyOutput_OptionalDeps(t *testing.T) {
	// bun why prefixes optional dependent lines with "optional ".
	// The parser must treat these identically to regular dependents.
	input := strings.NewReader(
		"@parcel/watcher-darwin-arm64@2.5.1\n" +
			"  └─ optional @parcel/watcher@2.5.1 (requires 2.5.1)\n\n" +
			"@parcel/watcher@2.5.1\n" +
			"  └─ my-app (requires 2.5.1)\n",
	)

	graph, err := parseWhyOutput(input)
	require.NoError(t, err)

	assert.Equal(t, pkgVersion("2.5.1"), graph.Packages["@parcel/watcher"])
	assert.Equal(t, pkgVersion("2.5.1"), graph.Packages["@parcel/watcher-darwin-arm64"])

	// Forward edge: @parcel/watcher optionally depends on @parcel/watcher-darwin-arm64.
	deps := graph.Dependencies[pkg{Name: "@parcel/watcher", Version: "2.5.1"}]
	assert.Contains(t, deps, pkg{Name: "@parcel/watcher-darwin-arm64", Version: "2.5.1"})
}
