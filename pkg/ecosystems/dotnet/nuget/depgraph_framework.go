package nuget

import (
	"context"
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// buildFrameworkDepGraph builds the dep graph for a packages.config or
// project.json project, mirroring snyk-nuget-plugin's dotnet-framework-parser.
//
// Every installed package is a direct dependency of the root, whether the
// project asked for it or something it depends on did. That is upstream's
// shape, and it is inherent to the format: a .NET Framework manifest is a
// flattened list with no record of who pulled what in. The .nuspec subtrees
// layered on top add structure without changing that.
func buildFrameworkDepGraph(
	ctx context.Context,
	rootName, rootVersion string,
	installed *packageSet,
	children map[string][]declaredPackage,
) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	graph := &frameworkGraph{
		edgeSet:   newEdgeSet(builder),
		installed: installed,
		children:  children,
		expanded:  make(map[string]struct{}),
	}
	rootNodeID := builder.GetRootNode().NodeID

	for _, pkg := range installed.packages {
		nodeID := pkgNodeID(pkg.name, pkg.version)

		builder.AddNode(nodeID, &godepgraph.PkgInfo{Name: pkg.name, Version: pkg.version})

		if err := graph.connect(rootNodeID, nodeID); err != nil {
			return nil, err
		}
	}

	// Second pass, so that every package is in the graph before any subtree
	// hangs off it. Iterating installed.packages rather than the children map
	// keeps the walk in manifest order, since Go map iteration is randomized.
	for _, pkg := range installed.packages {
		nodeID := pkgNodeID(pkg.name, pkg.version)

		declared, ok := children[pkg.name]
		if !ok {
			continue
		}

		if _, done := graph.expanded[nodeID]; done {
			continue
		}

		graph.expanded[nodeID] = struct{}{}

		if err := graph.addChildren(ctx, nodeID, declared, map[string]struct{}{nodeID: {}}); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// frameworkGraph carries the state the .nuspec walk needs.
type frameworkGraph struct {
	*edgeSet
	// installed is what is actually on disk, and it decides the version a child
	// node is reported at: a child found here is reported at the installed
	// version, not at whatever the parent's .nuspec asked for.
	//
	// The distinction matters because a .nuspec states a version *range* as
	// often as a version — "[1.0,2.0)" is legal there. A range only ever
	// reaches the graph for a package that is not installed, where it is the
	// only thing known about it.
	installed *packageSet
	// children maps a package name to what its .nuspec declares. A package with
	// no .nupkg on disk is absent rather than empty.
	children map[string][]declaredPackage
	// expanded holds the nodes whose own children have already been emitted, so
	// a subtree several packages share is walked once rather than once per route
	// that reaches it. What a package depends on follows from its name and
	// version alone, never from the route taken, so the first walk is as good as
	// any later one and the graph is the same either way.
	//
	// This is a complexity guard, not a correctness one: without it a chain of
	// shared dependencies is re-walked exponentially. onPath is what keeps the
	// graph acyclic.
	expanded map[string]struct{}
}

// addChildren connects a package's declared dependencies and recurses.
//
// Two guards, each solving a different problem.
//
// onPath is the chain of nodes from the start of this walk down to here. A
// child already on that chain would close a cycle, so that edge is skipped:
// dep graphs are consumed as acyclic. Nothing is lost by skipping it, because
// every installed package is already a direct child of the root — the edge
// would have added a route to a package, never a package. (snyk-nuget-plugin
// has no such guard and overflows its stack on a cyclic .nuspec graph.)
//
// g.expanded is the set of nodes whose children have already been emitted, and
// it keeps the walk linear. Without it a package reachable by two routes is
// re-walked once per route, which compounds: a chain of shared dependencies
// costs 2^depth.
//
// No `:pruned` leaf is emitted for either case. Those belong to the
// project.assets.json path, where a repeated edge carries meaning.
func (g *frameworkGraph) addChildren(
	ctx context.Context,
	parentNodeID string,
	children []declaredPackage,
	onPath map[string]struct{},
) error {
	// Cheap insurance: the walk is linear in the graph, but the graph comes
	// from files on disk.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("resolving dependencies: %w", err)
	}

	for _, child := range children {
		// An installed package is reported at the version on disk. One that is
		// not installed is reported at whatever the .nuspec asked for, which
		// may be a range rather than a version — upstream reports it verbatim
		// too, and it is the only thing known about the package.
		resolved, ok := g.installed.get(child.name)
		if !ok {
			resolved = child
		}

		childNodeID := pkgNodeID(resolved.name, resolved.version)

		if _, cycle := onPath[childNodeID]; cycle {
			continue
		}

		g.builder.AddNode(childNodeID, &godepgraph.PkgInfo{Name: resolved.name, Version: resolved.version})

		if err := g.connect(parentNodeID, childNodeID); err != nil {
			return err
		}

		grandchildren, ok := g.children[resolved.name]
		if !ok {
			continue
		}

		if _, done := g.expanded[childNodeID]; done {
			continue
		}

		g.expanded[childNodeID] = struct{}{}

		onPath[childNodeID] = struct{}{}
		err := g.addChildren(ctx, childNodeID, grandchildren, onPath)
		delete(onPath, childNodeID)

		if err != nil {
			return err
		}
	}

	return nil
}
