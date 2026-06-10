package pnpm

import (
	"fmt"
	"path/filepath"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "pnpm"

// depGraphResult pairs a built dep graph with the path to the package.json that
// describes it, relative to the scan root.
type depGraphResult struct {
	graph          *godepgraph.DepGraph
	pkgJSONRelPath string
}

// buildDepGraphs produces one dep graph per importer project from `pnpm list`
// output. Other workspace members appear as stop-set leaves in every graph
// (their subtrees are walked only in their own graph), preventing duplicated
// reporting across workspaces. The importer whose directory is skipDir (the
// Rush "rush-common" aggregate at the staged common/temp) is omitted; pass ""
// to skip nothing.
func buildDepGraphs(scanDir string, projects []listProject, skipDir string) ([]depGraphResult, error) {
	// Workspace members keyed by name → resolved version, so `link:` deps can be
	// rendered as the sibling project's real coordinates.
	wsVersions := make(map[string]string, len(projects))
	for _, p := range projects {
		if p.Name != "" {
			wsVersions[p.Name] = p.Version
		}
	}

	// Resolve symlinks so relative-path math is stable when the scan root and
	// pnpm's reported project paths disagree on symlinked prefixes (e.g. macOS
	// /var → /private/var for tmp staging dirs).
	scanBase := resolveSymlinks(scanDir)
	var skipResolved string
	if skipDir != "" {
		skipResolved = resolveSymlinks(skipDir)
	}

	var results []depGraphResult
	for i := range projects {
		p := projects[i]
		if p.Name == "" {
			continue
		}
		// Skip the synthetic aggregate importer by path (not by name, so a real
		// project that happens to be named "rush-common" is not dropped).
		if skipResolved != "" && resolveSymlinks(p.Path) == skipResolved {
			continue
		}

		g, err := buildSingleDepGraph(p, wsVersions)
		if err != nil {
			return nil, fmt.Errorf("building dep graph for %s: %w", p.Name, err)
		}

		relDir := "."
		if rel, err := filepath.Rel(scanBase, resolveSymlinks(p.Path)); err == nil && !strings.HasPrefix(rel, "..") {
			relDir = rel
		}
		results = append(results, depGraphResult{
			graph:          g,
			pkgJSONRelPath: filepath.Join(relDir, packageJSONFile),
		})
	}

	return results, nil
}

// resolveSymlinks returns the symlink-resolved path, or the input unchanged if
// resolution fails (e.g. path doesn't exist).
func resolveSymlinks(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

func buildSingleDepGraph(p listProject, wsVersions map[string]string) (*godepgraph.DepGraph, error) {
	rootVersion := p.Version
	if rootVersion == "" {
		rootVersion = defaultVersion
	}

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: p.Name, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[string]bool)   // nodes already added (dedup + cycle guard)
	edgesSeen := make(map[string]bool) // parent→child edges already connected

	// pnpm list --json reports the resolved tree under dependencies,
	// devDependencies, and optionalDependencies — it emits no separate
	// peerDependencies key. Satisfied peers already appear within the resolved
	// tree; a package's own declared peers are the consumer's responsibility.
	// So there is nothing further to read for peer deps (a deliberate
	// consequence of delegating resolution to pnpm, matching the npm resolver).
	for _, deps := range []map[string]listDep{p.Dependencies, p.DevDependencies, p.OptionalDependencies} {
		for name, d := range deps {
			if err := addDep(builder, rootNodeID, name, d, wsVersions, visited, edgesSeen); err != nil {
				return nil, err
			}
		}
	}

	return builder.Build(), nil
}

// addDep adds the dependency (name, d) to the graph and connects it to parentID.
// A workspace member (resolved via `link:` or present in wsVersions) is added as
// a leaf — its subtree belongs to its own graph and is not walked here.
func addDep(
	builder *godepgraph.Builder,
	parentID, name string,
	d listDep,
	wsVersions map[string]string,
	visited, edgesSeen map[string]bool,
) error {
	version := d.Version
	// A workspace cross-dependency is identified by pnpm's authoritative `link:`
	// version prefix — NOT by name. Keying on name alone would mis-flag a real
	// registry package that happens to share a name with a workspace project,
	// stop-set'ing it and silently dropping its subtree. Once a link is
	// confirmed, consult wsVersions only to render the sibling's real version
	// instead of the bare `link:<path>`.
	isWorkspace := strings.HasPrefix(version, "link:")
	if isWorkspace {
		if v, ok := wsVersions[name]; ok {
			version = v
		}
	}
	if version == "" {
		version = defaultVersion
	}

	id := name + "@" + version

	if !visited[id] {
		visited[id] = true
		builder.AddNode(id, &godepgraph.PkgInfo{Name: name, Version: version})

		if !isWorkspace {
			for childName, child := range d.Dependencies {
				if err := addDep(builder, id, childName, child, wsVersions, visited, edgesSeen); err != nil {
					return err
				}
			}
		}
	}

	// Connect once per (parent, child) edge. visited dedups nodes, not edges; a
	// package present under both dependencies and devDependencies would
	// otherwise yield a duplicate edge from the same parent.
	edgeKey := parentID + "\x00" + id
	if !edgesSeen[edgeKey] {
		edgesSeen[edgeKey] = true
		if err := builder.ConnectNodes(parentID, id); err != nil {
			return fmt.Errorf("connecting %s → %s: %w", parentID, id, err)
		}
	}

	return nil
}
