package nuget

import (
	"context"
	"errors"
	"fmt"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "nuget"

// buildDepGraph builds the dep graph for one target framework of one project.
// targetsKey must come from matchTargetsKey — a project's framework moniker is
// not always the `targets` key.
//
// Mirrors snyk-nuget-plugin's v3 parser, minus the runtime-assembly version
// overrides it reads from the host SDK's PackageOverrides.txt: that needs a .NET
// SDK, so the versions the assets file resolved are reported instead. See
// CMPA-714.
func buildDepGraph(ctx context.Context, assets *projectAssets, rootName, targetsKey string) (*godepgraph.DepGraph, error) {
	rootVersion := assets.Project.Version
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

	target, ok := assets.Targets.Get(targetsKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errNoResolvedPackages, targetsKey)
	}

	g := &graphBuilder{
		edgeSet:  newEdgeSet(builder),
		resolved: resolvePackages(&target),
	}

	direct := assets.directDependencies(targetsKey)

	// Declared dependencies but no packages means the restore did not complete.
	// The root-only graph that falls out of that would read as "no
	// dependencies", which is worse than reporting the failure.
	if len(direct) > 0 && len(g.resolved) == 0 {
		return nil, fmt.Errorf("%w: %s", errNoResolvedPackages, targetsKey)
	}

	if err := g.addChildren(ctx, builder.GetRootNode().NodeID, direct, nil); err != nil {
		return nil, err
	}

	return builder.Build(), nil
}

// errNoResolvedPackages marks a target framework whose package set is missing or
// empty.
var errNoResolvedPackages = errors.New("no resolved packages for target framework")

// edge identifies a parent/child pair already connected in the graph.
type edge struct {
	parent string
	child  string
}

// edgeSet wraps a builder so that an edge is added at most once. Both .NET
// resolution paths walk a shared subtree once per route that reaches it, and
// Builder.ConnectNodes appends without checking, whereas the graphlib
// snyk-nuget-plugin builds on treats an edge as a set member. Without this the
// same dependency would appear several times in a node's deps.
type edgeSet struct {
	builder *godepgraph.Builder
	edges   map[edge]struct{}
}

func newEdgeSet(builder *godepgraph.Builder) *edgeSet {
	return &edgeSet{builder: builder, edges: make(map[edge]struct{})}
}

// connect adds an edge unless it is already present.
func (e *edgeSet) connect(parentNodeID, childNodeID string) error {
	pair := edge{parent: parentNodeID, child: childNodeID}
	if _, seen := e.edges[pair]; seen {
		return nil
	}

	if err := e.builder.ConnectNodes(parentNodeID, childNodeID); err != nil {
		return fmt.Errorf("connecting %s to %s: %w", parentNodeID, childNodeID, err)
	}

	e.edges[pair] = struct{}{}

	return nil
}

type graphBuilder struct {
	*edgeSet
	resolved map[string]resolvedPackage
}

// addChildren connects each named dependency to parentNodeID and recurses,
// reproducing recursivelyPopulateNodes in snyk-nuget-plugin's v3 parser.
//
// visited is copied once per call and then mutated across this parent's
// children, so a child is pruned when it appears among its own ancestors or
// among siblings already walked at this level. That asymmetry is upstream's and
// decides which edges become pruned leaves, so it is reproduced rather than
// tidied up.
func (g *graphBuilder) addChildren(
	ctx context.Context,
	parentNodeID string,
	childNames []string,
	visited map[string]struct{},
) error {
	// A shared subtree is re-walked once per path reaching it, matching upstream,
	// so a pathological file can run long. Cancellation is the way out; bounding
	// the work would diverge from upstream.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("resolving dependencies: %w", err)
	}

	local := make(map[string]struct{}, len(visited)+len(childNames))
	for id := range visited {
		local[id] = struct{}{}
	}

	for _, childName := range childNames {
		if isFilteredPackage(childName) {
			continue
		}

		// Expected rather than wrong: framework references such as
		// Microsoft.NETCore.App are declared but never resolved as packages.
		pkg, ok := g.resolved[strings.ToLower(childName)]
		if !ok {
			continue
		}

		info := &godepgraph.PkgInfo{Name: pkg.name, Version: pkg.version}
		childNodeID := pkgNodeID(pkg.name, pkg.version)

		if _, seen := local[childNodeID]; seen {
			prunedNodeID := childNodeID + prunedNodeSuffix

			g.builder.AddNode(prunedNodeID, info, godepgraph.WithNodeInfo(&godepgraph.NodeInfo{
				Labels: map[string]string{prunedLabelKey: prunedLabelValue},
			}))

			if err := g.connect(parentNodeID, prunedNodeID); err != nil {
				return err
			}

			continue
		}

		g.builder.AddNode(childNodeID, info)

		if err := g.connect(parentNodeID, childNodeID); err != nil {
			return err
		}

		local[childNodeID] = struct{}{}

		if err := g.addChildren(ctx, childNodeID, pkg.deps.Keys(), local); err != nil {
			return err
		}
	}

	return nil
}

// pkgNodeID is the graph identity of a package, matching the dep-graph
// library's own getPkgID.
func pkgNodeID(name, version string) string {
	return name + "@" + version
}
