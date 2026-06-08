package npm

import (
	"fmt"
	"path/filepath"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "npm"

// depGraphResult pairs a built dep graph with the relative path to the
// package.json that describes it (relative to the directory containing
// package-lock.json).
//
// For the root project this is always "package.json". For a workspace package
// whose resolved URI is "file:packages/a" the path is "packages/a/package.json".
type depGraphResult struct {
	graph          *godepgraph.DepGraph
	pkgJSONRelPath string
}

// buildDepGraphs produces one dep graph per workspace package, plus one for
// the root project. Workspace packages terminate the DFS in every graph they
// appear in as a dependency: their subtrees are walked only in their own dep
// graph, preventing duplicated vulnerability reporting across workspaces.
//
// workspacePaths maps workspace package name → on-disk relative directory
// (relative to the lockfile dir) as parsed from the lockfile. It overrides
// the malformed `file:../../...` paths npm ls reports.
//
// If the project contains no workspace packages, a single-element slice is
// returned containing the root dep graph.
func buildDepGraphs(rootName, rootVersion string, root *listResponse, workspacePaths map[string]string) ([]depGraphResult, error) {
	forward, workspaces, rootDeps := collectAdjacency(root, workspacePaths)

	// Set view of workspace pkg IDs — used as the stop-set when building the
	// root graph so workspace subtrees aren't duplicated under the root.
	allWS := make(map[string]struct{}, len(workspaces))
	for id := range workspaces {
		allWS[id] = struct{}{}
	}

	// Build the root dep graph. Workspace packages appear as leaves — their
	// subtrees live in their own dep graphs.
	rootGraph, err := buildSingleDepGraph(rootName, rootVersion, rootDeps, forward, allWS)
	if err != nil {
		return nil, fmt.Errorf("building root dep graph: %w", err)
	}

	results := []depGraphResult{{graph: rootGraph, pkgJSONRelPath: packageJSONFile}}

	// One dep graph per workspace package. Each stops at other workspace
	// packages so their subtrees are not duplicated.
	for wsID, wsDir := range workspaces {
		name, version := splitPkgID(wsID)

		wsSeeds := make(map[string]struct{}, len(forward[wsID]))
		for dep := range forward[wsID] {
			wsSeeds[dep] = struct{}{}
		}

		// Stop at other workspace packages; wsID itself is this graph's root.
		otherWS := make(map[string]struct{}, len(workspaces))
		for id := range workspaces {
			if id != wsID {
				otherWS[id] = struct{}{}
			}
		}

		wsGraph, err := buildSingleDepGraph(name, version, wsSeeds, forward, otherWS)
		if err != nil {
			return nil, fmt.Errorf("building dep graph for %s: %w", wsID, err)
		}

		pkgJSONRelPath := filepath.Join(wsDir, packageJSONFile)
		results = append(results, depGraphResult{graph: wsGraph, pkgJSONRelPath: pkgJSONRelPath})
	}

	return results, nil
}

// collectAdjacency walks the nested `npm ls --json` tree and produces a
// forward adjacency map plus a workspace registry.
//
//   - forward[A] = {B, C} means A directly depends on B and C.
//   - workspaces[id] = relative directory of the workspace's package.json.
//   - rootDeps is the set of IDs the root project directly depends on.
//
// Workspaces are identified by their `resolved` field beginning with "file:";
// for those, we encode their resolved URI into the pkg ID so they're
// distinguishable from any same-named registry package and produce a stable
// stopAt key in the dep-graph build pass.
func collectAdjacency(root *listResponse, workspacePaths map[string]string) (
	forward map[string]map[string]struct{},
	workspaces map[string]string,
	rootDeps map[string]struct{},
) {
	forward = make(map[string]map[string]struct{})
	workspaces = make(map[string]string)
	rootDeps = make(map[string]struct{})

	onPath := make(map[string]bool)

	for name, dep := range root.Dependencies {
		id := pkgID(name, dep, workspacePaths)
		rootDeps[id] = struct{}{}
		walkDep(id, name, dep, forward, workspaces, workspacePaths, onPath)
	}

	return forward, workspaces, rootDeps
}

// walkDep recursively descends a listResponseDep, accumulating edges into
// forward[id] from every appearance of the pkg in the npm ls tree.
//
// We deliberately walk EVERY appearance — not just the first — because npm ls
// reports the same pkg at multiple positions in its tree with INCONSISTENT
// child sets: one canonical listing shows the full subtree, while the rest are
// stubs with `dependencies: {}` (since npm collapses duplicates to avoid bloat
// in the JSON output). A first-appearance-wins visited check loses the full
// subtree whenever a stub is encountered first, dropping packages that should
// be in the graph. Seen in practice with deep transitive trees (e.g. lodash 2.x
// internal helpers).
//
// `onPath` is the set of ids currently on the recursion stack — used purely
// for cycle protection against pathological inputs. Real npm ls JSON is
// acyclic by construction (cycles are flattened to leaf references), but the
// guard keeps us safe against unit-test fixtures and any future quirk.
func walkDep(
	id, name string,
	dep *listResponseDep,
	forward map[string]map[string]struct{},
	workspaces map[string]string,
	workspacePaths map[string]string,
	onPath map[string]bool,
) {
	if wsDir, ok := workspacePaths[name]; ok && strings.HasPrefix(dep.Resolved, "file:") {
		workspaces[id] = wsDir
	}

	if _, ok := forward[id]; !ok {
		forward[id] = make(map[string]struct{})
	}

	if onPath[id] {
		return
	}
	onPath[id] = true
	defer delete(onPath, id)

	for childName, childDep := range dep.Dependencies {
		childID := pkgID(childName, childDep, workspacePaths)
		forward[id][childID] = struct{}{}
		walkDep(childID, childName, childDep, forward, workspaces, workspacePaths, onPath)
	}
}

// pkgID returns the canonical "name@version" identifier for a dep node.
//
// For workspace packages, the canonical workspace directory (from the lockfile,
// not from npm ls's mangled "file:../../..." paths) is encoded as the version
// using the "file:" prefix. This keeps workspace nodes distinct from registry
// packages of the same name and gives the dep-graph stop-set a stable key.
//
// A dep is treated as a workspace only when BOTH (a) its name appears in
// workspacePaths from the lockfile and (b) its Resolved field begins with
// "file:" in npm ls output — the AND guards against the unlikely case of a
// registry package sharing a name with a workspace.
func pkgID(name string, dep *listResponseDep, workspacePaths map[string]string) string {
	if wsDir, ok := workspacePaths[name]; ok && strings.HasPrefix(dep.Resolved, "file:") {
		return name + "@file:" + wsDir
	}

	version := dep.Version
	if version == "" {
		version = defaultVersion
	}
	return name + "@" + version
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
// leaf only.
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

// splitPkgID splits a full package ID ("name@version") at the last '@' that is
// not at position 0, returning the bare name and resolved version separately.
//
// Examples:
//
//	"ms@2.0.0"                                → ("ms", "2.0.0")
//	"@types/node@25.5.2"                      → ("@types/node", "25.5.2")
//	"@workspace/logger@file:packages/logger"  → ("@workspace/logger", "file:packages/logger")
func splitPkgID(id string) (name, version string) {
	i := strings.LastIndex(id, "@")
	if i <= 0 {
		return id, ""
	}

	return id[:i], id[i+1:]
}
