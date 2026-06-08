package swiftpm

import (
	"fmt"
	"regexp"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "swift"

// registryIdentityRe matches the Swift Package Registry "scope.package-name"
// identity format (e.g. "apple.swift-argument-parser"). When swift reports a
// dep via its registry identity rather than a URL, we map it to the
// canonical github.com/scope/name form for vuln-lookup parity with the
// legacy plugin.
var registryIdentityRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9][a-zA-Z0-9-]*$`)

// packageNameFromURL normalises a swift dep's URL/identity into the canonical
// package name used as the dep-graph node name.
//
// Mirrors snyk-swiftpm-plugin/lib/compute-depgraph.ts:packageNameFromUrl:
//
//   - "https://github.com/apple/swift-nio.git" → "github.com/apple/swift-nio"
//   - "http://example.com/foo.git"             → "example.com/foo"
//   - "apple.swift-argument-parser"            → "github.com/apple/swift-argument-parser"
//   - anything else                            → returned unchanged (path: deps, etc.)
func packageNameFromURL(url string) string {
	switch {
	case strings.HasPrefix(url, "https://"):
		return strings.TrimSuffix(strings.TrimPrefix(url, "https://"), ".git")
	case strings.HasPrefix(url, "http://"):
		return strings.TrimSuffix(strings.TrimPrefix(url, "http://"), ".git")
	case registryIdentityRe.MatchString(url):
		dot := strings.Index(url, ".")
		return "github.com/" + url[:dot] + "/" + url[dot+1:]
	default:
		return url
	}
}

// buildDepGraph converts a parsed depTreeNode tree into a @snyk/dep-graph.
//
// Identity contract (mirrors legacy snyk-swiftpm-plugin):
//   - rootPkg.name comes from Package.swift's Package(name:); falls back to
//     the JSON root's `name` field. Identity follows the same precedence.
//   - rootPkg.version uses the swift-reported version. swift emits
//     "unspecified" for the root and for path/branch deps — we preserve
//     that string for parity. A truly empty version is replaced with
//     defaultVersion to keep dep-graph builder happy.
//   - Non-root nodes use packageNameFromURL(node.url) + "@" + node.version.
func buildDepGraph(rootName string, root *depTreeNode) (*godepgraph.DepGraph, error) {
	if rootName == "" {
		rootName = root.Name
	}

	rootVersion := root.Version
	if rootVersion == "" {
		rootVersion = defaultVersion
	}

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[string]bool)

	for _, child := range root.Dependencies {
		if err := addNode(builder, rootNodeID, child, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addNode adds node to the dep graph (if not already visited) and connects
// it to parentID. The recursion is bounded by visited; cycles in the swift
// tree (possible via path: / branch: deps) terminate cleanly.
func addNode(
	builder *godepgraph.Builder,
	parentID string,
	node *depTreeNode,
	visited map[string]bool,
) error {
	name := packageNameFromURL(node.URL)
	version := node.Version
	if version == "" {
		version = defaultVersion
	}

	nodeID := name + "@" + version

	connect := func() error {
		if err := builder.ConnectNodes(parentID, nodeID); err != nil {
			return fmt.Errorf("connecting %s → %s: %w", parentID, nodeID, err)
		}
		return nil
	}

	if !visited[nodeID] {
		visited[nodeID] = true

		builder.AddNode(nodeID, &godepgraph.PkgInfo{Name: name, Version: version})

		for _, child := range node.Dependencies {
			if err := addNode(builder, nodeID, child, visited); err != nil {
				return err
			}
		}
	}

	return connect()
}
