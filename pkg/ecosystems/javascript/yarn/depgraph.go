package yarn

import (
	"fmt"
	"path/filepath"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "yarn"

// depGraphResult pairs a built dep graph with the path to its describing
// package.json (relative to the directory containing yarn.lock). The root
// project's result is always "package.json"; workspace results use the
// workspace's declared dir.
type depGraphResult struct {
	graph          *godepgraph.DepGraph
	pkgJSONRelPath string
}

// buildDepGraphs produces one dep graph per workspace package plus one for
// the root project. Workspace packages terminate the DFS in every graph they
// appear in as a dependency — their subtrees are walked only in their own
// dep graph, preventing duplicated vulnerability reporting across workspaces.
func buildDepGraphs(rootName, rootVersion string, out *parsedOutput) ([]depGraphResult, error) {
	wsSet := make(map[string]struct{}, len(out.Workspaces))
	for id := range out.Workspaces {
		wsSet[id] = struct{}{}
	}

	seeds := make(map[string]struct{}, len(out.ProdDeps)+len(out.DevDeps))
	for _, id := range out.ProdDeps {
		seeds[id] = struct{}{}
	}
	for _, id := range out.DevDeps {
		seeds[id] = struct{}{}
	}

	rootGraph, err := buildSingleDepGraph(rootName, rootVersion, seeds, out.Graph, wsSet)
	if err != nil {
		return nil, fmt.Errorf("building root dep graph: %w", err)
	}
	results := []depGraphResult{{graph: rootGraph, pkgJSONRelPath: packageJSONFile}}

	for wsID, info := range out.Workspaces {
		wsSeeds := make(map[string]struct{}, len(out.Graph[wsID]))
		for dep := range out.Graph[wsID] {
			wsSeeds[dep] = struct{}{}
		}

		otherWS := make(map[string]struct{}, len(wsSet))
		for id := range wsSet {
			if id != wsID {
				otherWS[id] = struct{}{}
			}
		}

		wsGraph, err := buildSingleDepGraph(info.Name, info.Version, wsSeeds, out.Graph, otherWS)
		if err != nil {
			return nil, fmt.Errorf("building dep graph for %s: %w", wsID, err)
		}

		pkgJSONRelPath := packageJSONFile
		if info.Dir != "" && info.Dir != "." {
			pkgJSONRelPath = filepath.Join(info.Dir, packageJSONFile)
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
	forward forwardGraph,
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
	forward forwardGraph,
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

// splitPkgID splits a yarn package ID at the last '@' that isn't at position
// 0, returning the bare name and a cleaned version separately. Used only to
// populate Snyk PkgInfo{Name, Version}; the graph's node ID stays as the raw
// id so multiple resolutions of the same package don't collide.
//
// Examples:
//
//	"accepts@1.3.7"                               → ("accepts",      "1.3.7")
//	"@types/node@25.5.2"                          → ("@types/node",  "25.5.2")
//	"debug@npm:4.3.1"                             → ("debug",        "4.3.1")
//	"@scope/pkg@npm:1.2.3"                        → ("@scope/pkg",   "1.2.3")
//	"logger@workspace:packages/logger"            → ("logger",       "workspace:packages/logger")
func splitPkgID(id string) (name, version string) {
	i := strings.LastIndex(id, "@")
	if i <= 0 {
		return id, ""
	}
	return id[:i], stripProtocol(id[i+1:])
}

// stripProtocol drops Berry's "npm:" prefix from a version specifier. Other
// protocols (workspace:, file:, patch:, git:) are kept intact because their
// payload carries meaningful information and there is no plain version to
// extract.
func stripProtocol(v string) string {
	return strings.TrimPrefix(v, "npm:")
}
