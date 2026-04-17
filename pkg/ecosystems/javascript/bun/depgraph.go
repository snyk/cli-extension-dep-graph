package bun

import (
	"fmt"
	"path/filepath"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// depGraphResult pairs a built dep graph with the relative path to the
// package.json that describes it (relative to the directory containing bun.lock).
//
// For the root project this is always "package.json". For a workspace package
// whose ID is "name@workspace:packages/a" the path is "packages/a/package.json".
type depGraphResult struct {
	graph          *godepgraph.DepGraph
	pkgJSONRelPath string
}

const pkgManager = "bun"

// buildDepGraphs produces one dep graph per workspace package, plus one for the
// root project. Workspace packages terminate the DFS in every graph they appear
// in as a dependency: their subtrees are walked only in their own dep graph,
// preventing duplicated vulnerability reporting across workspaces.
//
// Each result carries the relative path to its package.json (relative to the
// directory containing bun.lock). The root result is always "package.json";
// workspace results use the path encoded in the workspace ID
// (e.g. "name@workspace:packages/a" → "packages/a/package.json").
//
// If the project contains no workspace packages, a single-element slice is
// returned containing the root dep graph.
func buildDepGraphs(rootName, rootVersion string, out *whyOutput) ([]depGraphResult, error) {
	wsPkgs := workspacePkgs(out.Graph)
	forward := buildForward(out.Graph)

	// Root dep graph — seeds from all direct root deps; workspace packages are leaves.
	seeds := make(map[string]struct{}, len(out.ProdDeps)+len(out.DevDeps))
	for _, id := range out.ProdDeps {
		seeds[id] = struct{}{}
	}
	for _, id := range out.DevDeps {
		seeds[id] = struct{}{}
	}

	rootGraph, err := buildSingleDepGraph(rootName, rootVersion, seeds, forward, wsPkgs)
	if err != nil {
		return nil, fmt.Errorf("building root dep graph: %w", err)
	}

	results := []depGraphResult{{graph: rootGraph, pkgJSONRelPath: packageJSONFile}}

	// One dep graph per workspace package. Each stops at other workspace
	// packages so their subtrees are not duplicated.
	for wsID := range wsPkgs {
		name, version := splitPkgID(wsID)

		// Derive the workspace package.json path from the workspace: version specifier.
		// e.g. "workspace:packages/a" → "packages/a/package.json"
		wsDir := strings.TrimPrefix(version, "workspace:")
		pkgJSONRelPath := filepath.Join(wsDir, packageJSONFile)

		wsSeeds := make(map[string]struct{}, len(forward[wsID]))
		for dep := range forward[wsID] {
			wsSeeds[dep] = struct{}{}
		}

		// Stop at other workspace packages; wsID itself is the root here, not a dep.
		otherWS := make(map[string]struct{}, len(wsPkgs))
		for id := range wsPkgs {
			if id != wsID {
				otherWS[id] = struct{}{}
			}
		}

		wsGraph, err := buildSingleDepGraph(name, version, wsSeeds, forward, otherWS)
		if err != nil {
			return nil, fmt.Errorf("building dep graph for %s: %w", wsID, err)
		}

		results = append(results, depGraphResult{graph: wsGraph, pkgJSONRelPath: pkgJSONRelPath})
	}

	return results, nil
}

// buildSingleDepGraph constructs one dep graph rooted at rootName/rootVersion.
// It DFS-walks from seeds through forward adjacency, stopping at any node in
// stopAt (adding it as a leaf but not recursing into its dependencies).
func buildSingleDepGraph(
	rootName, rootVersion string,
	seeds map[string]struct{},
	forward map[string]map[string]struct{},
	stopAt map[string]struct{},
) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[string]bool)

	for id := range seeds {
		if err := addNode(builder, rootNodeID, id, forward, stopAt, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addNode adds id to the dep graph (if not already visited) and connects it to
// parentID. If id is in stopAt, its subtree is not walked — it appears as a
// leaf only. Called recursively for all of id's forward dependencies.
func addNode(
	builder *godepgraph.Builder,
	parentID, id string,
	forward map[string]map[string]struct{},
	stopAt map[string]struct{},
	visited map[string]bool,
) error {
	connectNode := func() error {
		if err := builder.ConnectNodes(parentID, id); err != nil {
			return fmt.Errorf("connecting %s → %s: %w", parentID, id, err)
		}
		return nil
	}

	if !visited[id] {
		visited[id] = true

		name, version := splitPkgID(id)
		builder.AddNode(id, &godepgraph.PkgInfo{Name: name, Version: version})

		if _, stop := stopAt[id]; stop {
			// Don't walk deps of stop-set nodes; they are roots of their own dep graphs.
			// but ensure that we do connect them.
			return connectNode()
		}
		for dep := range forward[id] {
			if err := addNode(builder, id, dep, forward, stopAt, visited); err != nil {
				return err
			}
		}
	}

	return connectNode()
}

// buildForward inverts the reverse graph into a forward adjacency map.
// forward[A] = {B, C} means A directly depends on B and C.
func buildForward(graph reverseGraph) map[string]map[string]struct{} {
	forward := make(map[string]map[string]struct{}, len(graph))
	for id, dependents := range graph {
		if forward[id] == nil {
			forward[id] = make(map[string]struct{})
		}

		for dep := range dependents {
			// dep depends on id → forward edge: dep → id
			if forward[dep] == nil {
				forward[dep] = make(map[string]struct{})
			}

			forward[dep][id] = struct{}{}
		}
	}

	return forward
}

// workspacePkgs returns the set of package IDs whose version starts with
// "workspace:", identifying them as local workspace packages.
func workspacePkgs(graph reverseGraph) map[string]struct{} {
	ws := make(map[string]struct{})

	for id := range graph {
		_, version := splitPkgID(id)
		if strings.HasPrefix(version, "workspace:") {
			ws[id] = struct{}{}
		}
	}

	return ws
}

// splitPkgID splits a full package ID ("name@version") at the last '@' that is
// not at position 0, returning the bare name and resolved version separately.
// This is used only to satisfy the Snyk dep graph builder's PkgInfo{Name, Version}.
//
// Examples:
//
//	"ms@2.0.0"                                    → ("ms", "2.0.0")
//	"@types/node@25.5.2"                          → ("@types/node", "25.5.2")
//	"@workspace/logger@workspace:packages/logger" → ("@workspace/logger", "workspace:packages/logger")
func splitPkgID(id string) (name, version string) {
	i := strings.LastIndex(id, "@")
	if i <= 0 {
		return id, ""
	}

	return id[:i], id[i+1:]
}
