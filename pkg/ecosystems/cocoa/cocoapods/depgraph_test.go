package cocoapods

import (
	"strings"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeByID locates a node by its NodeID for assertions.
func nodeByID(t *testing.T, g *depgraph.DepGraph, id string) *depgraph.Node {
	t.Helper()
	for i := range g.Graph.Nodes {
		if g.Graph.Nodes[i].NodeID == id {
			return &g.Graph.Nodes[i]
		}
	}
	t.Fatalf("no node with ID %q", id)
	return nil
}

func depNodeIDs(n *depgraph.Node) []string {
	ids := make([]string, len(n.Deps))
	for i, d := range n.Deps {
		ids[i] = d.NodeID
	}
	return ids
}

func TestBuildDepGraph_Simple(t *testing.T) {
	lock, err := ParseLockfile(strings.NewReader(simpleLockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "my-app", "0.0.0")
	require.NoError(t, err)

	assert.Equal(t, pkgManagerName, g.PkgManager.Name)
	assert.Equal(t, "1.10.0", g.PkgManager.Version)
	assert.Len(t, g.PkgManager.Repositories, 1)
	assert.Equal(t, "trunk", g.PkgManager.Repositories[0].Alias)

	root := nodeByID(t, g, "root-node")
	assert.Equal(t, []string{"Reachability"}, depNodeIDs(root))

	reach := nodeByID(t, g, "Reachability")
	require.NotNil(t, reach.Info)
	assert.Equal(t, "3c8fe9643e52184d17f207e781cd84158da8c02b", reach.Info.Labels[labelChecksum])
	assert.Equal(t, "trunk", reach.Info.Labels[labelRepository])
}

// TestBuildDepGraph_SubspecDedup proves subspecs collapse onto their
// root spec's node — AFNetworking/NSURLConnection and
// AFNetworking/Security must not appear as separate nodes.
func TestBuildDepGraph_SubspecDedup(t *testing.T) {
	lock, err := ParseLockfile(strings.NewReader(withSubspecsLockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "my-app", "0.0.0")
	require.NoError(t, err)

	// Only one AFNetworking node (the root spec) — the two subspecs
	// dedupe onto it.
	count := 0
	for _, n := range g.Graph.Nodes {
		if n.NodeID == "AFNetworking" {
			count++
		}
	}
	assert.Equal(t, 1, count, "subspecs must not produce duplicate nodes")

	// No subspec node should leak out as its own dep graph node.
	for _, n := range g.Graph.Nodes {
		assert.NotContains(t, n.NodeID, "/", "subspecs must dedupe onto root spec name")
	}

	root := nodeByID(t, g, "root-node")
	assert.Equal(t, []string{"AFNetworking"}, depNodeIDs(root))

	// AFNetworking → AFNetworking subspec edges are self-edges after
	// dedup and must be elided.
	af := nodeByID(t, g, "AFNetworking")
	assert.Empty(t, af.Deps, "self-edges from subspec collapse must be dropped")
}

func TestBuildDepGraph_LabelsPreserved_ExternalSourcesAndCheckout(t *testing.T) {
	const lockfile = `PODS:
  - Just (0.6.0)

DEPENDENCIES:
  - Just

EXTERNAL SOURCES:
  Just:
    :branch: swift-5
    :git: https://github.com/iina/Just

CHECKOUT OPTIONS:
  Just:
    :commit: d0ae3f9bc2d6bf247b19217764a096bbac55f007
    :git: https://github.com/iina/Just

SPEC CHECKSUMS:
  Just: abc

COCOAPODS: 1.10.0
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "my-app", "0.0.0")
	require.NoError(t, err)

	just := nodeByID(t, g, "Just")
	require.NotNil(t, just.Info)
	labels := just.Info.Labels

	// Exact label keys preserved from the legacy plugin.
	assert.Equal(t, "abc", labels[labelChecksum])
	assert.Equal(t, "https://github.com/iina/Just", labels[labelExternalSourceGit])
	assert.Equal(t, "swift-5", labels[labelExternalSourceBranch])
	assert.Equal(t, "https://github.com/iina/Just", labels[labelCheckoutOptionsGit])
	assert.Equal(t, "d0ae3f9bc2d6bf247b19217764a096bbac55f007", labels[labelCheckoutOptionsCommit])

	// Unset fields must NOT show up as empty-string labels.
	_, hasTag := labels[labelExternalSourceTag]
	assert.False(t, hasTag, "empty ExternalSourceTag must be omitted, not stored as empty string")
}

// TestBuildDepGraph_LabelsAbsentForPlainPod confirms that pods without
// repository, external source, or checkout options carry only the
// checksum label — no nulls, no empty strings.
func TestBuildDepGraph_LabelsAbsentForPlainPod(t *testing.T) {
	const lockfile = `PODS:
  - Foo (1.0.0)

DEPENDENCIES:
  - Foo

SPEC CHECKSUMS:
  Foo: 0fffffff
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "app", "0.0.0")
	require.NoError(t, err)

	foo := nodeByID(t, g, "Foo")
	require.NotNil(t, foo.Info)
	assert.Equal(t, map[string]string{labelChecksum: "0fffffff"}, foo.Info.Labels)
}

func TestBuildDepGraph_VersionExtraction(t *testing.T) {
	const lockfile = `PODS:
  - Foo (1.2.3)
  - Bar (4.5.6)

DEPENDENCIES:
  - Foo (= 1.2.3)
  - Bar

SPEC CHECKSUMS:
  Foo: aa
  Bar: bb

COCOAPODS: 1.16.2
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "app", "0.0.0")
	require.NoError(t, err)

	assert.Equal(t, "1.16.2", g.PkgManager.Version)

	foo := nodeByID(t, g, "Foo")
	var fooPkg *depgraph.Pkg
	for i := range g.Pkgs {
		if g.Pkgs[i].ID == foo.PkgID {
			fooPkg = &g.Pkgs[i]
			break
		}
	}
	require.NotNil(t, fooPkg)
	assert.Equal(t, "1.2.3", fooPkg.Info.Version)
}

// TestBuildDepGraph_CocoapodsVersionFallback asserts that a lockfile
// missing the COCOAPODS field reports "unknown" — matches legacy.
func TestBuildDepGraph_CocoapodsVersionFallback(t *testing.T) {
	const lockfile = `PODS:
  - Foo (1.0.0)

DEPENDENCIES:
  - Foo

SPEC CHECKSUMS:
  Foo: abc
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "app", "0.0.0")
	require.NoError(t, err)
	assert.Equal(t, defaultCocoapodsVersion, g.PkgManager.Version)
}

// TestBuildDepGraph_TransitiveEdgesPointAtRoot confirms that a
// transitive edge pointing at a subspec is rewritten to the subspec's
// root, matching the dedup strategy.
func TestBuildDepGraph_TransitiveEdgesPointAtRoot(t *testing.T) {
	const lockfile = `PODS:
  - AFOAuth1Client (0.4.0):
    - AFNetworking (~> 2.5)
  - AFNetworking (2.5.4):
    - AFNetworking/NSURLConnection (= 2.5.4)
  - AFNetworking/NSURLConnection (2.5.4)

DEPENDENCIES:
  - AFOAuth1Client

SPEC CHECKSUMS:
  AFOAuth1Client: aa
  AFNetworking: bb
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "app", "0.0.0")
	require.NoError(t, err)

	client := nodeByID(t, g, "AFOAuth1Client")
	assert.Equal(t, []string{"AFNetworking"}, depNodeIDs(client),
		"transitive dep on AFNetworking must connect to the deduped root node")
}

// TestBuildDepGraph_DroppedEdgesToMissingPods verifies the legacy
// behaviour that transitive edges pointing at pods which never appear
// in PODS (platform-specific subspecs) are silently dropped rather
// than fabricated.
func TestBuildDepGraph_DroppedEdgesToMissingPods(t *testing.T) {
	const lockfile = `PODS:
  - Foo (1.0.0):
    - GhostDep
  - Foo/Sub (1.0.0)

DEPENDENCIES:
  - Foo

SPEC CHECKSUMS:
  Foo: abc
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "app", "0.0.0")
	require.NoError(t, err)

	foo := nodeByID(t, g, "Foo")
	for _, dep := range foo.Deps {
		assert.NotEqual(t, "GhostDep", dep.NodeID, "missing pods must be dropped, not fabricated")
	}
}

// TestBuildDepGraph_RepositoriesMatchSpecRepoKeys ensures all SPEC
// REPOS keys (whether name or URL) appear as PkgManager repositories.
func TestBuildDepGraph_RepositoriesMatchSpecRepoKeys(t *testing.T) {
	const lockfile = `PODS:
  - GzipSwift (5.1.1)

DEPENDENCIES:
  - GzipSwift

SPEC REPOS:
  https://github.com/cocoapods/specs.git:
    - GzipSwift

SPEC CHECKSUMS:
  GzipSwift: abc
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	g, err := BuildDepGraph(lock, "app", "0.0.0")
	require.NoError(t, err)

	require.Len(t, g.PkgManager.Repositories, 1)
	assert.Equal(t, "https://github.com/cocoapods/specs.git", g.PkgManager.Repositories[0].Alias)

	g2 := nodeByID(t, g, "GzipSwift")
	require.NotNil(t, g2.Info)
	assert.Equal(t, "https://github.com/cocoapods/specs.git", g2.Info.Labels[labelRepository])
}
