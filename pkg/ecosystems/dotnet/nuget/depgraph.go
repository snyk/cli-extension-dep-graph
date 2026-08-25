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
		builder:  builder,
		resolved: resolvePackages(&target),
		edges:    make(map[edge]struct{}),
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

type graphBuilder struct {
	builder  *godepgraph.Builder
	resolved map[string]resolvedPackage
	edges    map[edge]struct{}
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
		childNodeID := nodeID(pkg)

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

// connect adds an edge unless it is already present. The builder appends
// without checking, while upstream's graphlib treats an edge as a set member —
// and upstream re-walks shared subtrees, so this is what keeps the two graphs
// the same shape.
func (g *graphBuilder) connect(parentNodeID, childNodeID string) error {
	e := edge{parent: parentNodeID, child: childNodeID}
	if _, seen := g.edges[e]; seen {
		return nil
	}

	if err := g.builder.ConnectNodes(parentNodeID, childNodeID); err != nil {
		return fmt.Errorf("connecting %s to %s: %w", parentNodeID, childNodeID, err)
	}

	g.edges[e] = struct{}{}

	return nil
}

// nodeID is the graph identity of a resolved package, matching the dep-graph
// library's own getPkgID.
func nodeID(pkg resolvedPackage) string {
	return pkg.name + "@" + pkg.version
}
