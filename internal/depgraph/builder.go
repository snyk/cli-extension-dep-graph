// TODO(uv): this is copied from the `dep-graph-go` library. We should open-source that code and import it here.
package depgraph

import (
	"errors"
	"fmt"
)

type Builder struct {
	schemaVersion string
	rootNodeID    string
	rootPkgID     string
	pkgManager    *PkgManager
	pkgs          map[string]*Pkg
	nodes         map[string]*Node
}

const (
	schemaVersion = "1.3.0"
	rootNodeID    = "root-node"
)

func NewBuilder(pkgManager *PkgManager, rootPkg *PkgInfo) (*Builder, error) {
	if pkgManager == nil {
		return nil, errors.New("cannot create builder without a package manager")
	}

	if rootPkg == nil {
		rootPkg = &PkgInfo{
			Name:    "_root",
			Version: "0.0.0",
		}
	}

	b := &Builder{
		schemaVersion: schemaVersion,
		pkgManager:    pkgManager,
		rootNodeID:    rootNodeID,
		rootPkgID:     getPkgID(rootPkg),
		pkgs:          make(map[string]*Pkg),
		nodes:         make(map[string]*Node),
	}

	b.addNode(b.rootNodeID, rootPkg)

	return b, nil
}

func (b *Builder) Build() *DepGraph {
	dg := &DepGraph{
		SchemaVersion: b.schemaVersion,
		PkgManager:    *b.pkgManager,
		Pkgs:          b.GetPkgs(),
		rootPkg:       b.pkgs[b.rootPkgID],
		pkgIdx:        make(map[string]*Pkg),
		Graph: Graph{
			RootNodeID: b.rootNodeID,
			Nodes:      make([]Node, 0, len(b.nodes)),
		},
	}

	for nodeID, node := range b.nodes {
		pkg := b.pkgs[node.PkgID]
		dg.pkgIdx[pkg.ID] = pkg

		dg.Graph.Nodes = append(dg.Graph.Nodes, Node{
			NodeID: nodeID,
			PkgID:  node.PkgID,
			Deps:   node.Deps,
		})
	}

	return dg
}

func (b *Builder) GetPkgManager() *PkgManager {
	return b.pkgManager
}

func (b *Builder) GetPkgs() []Pkg {
	pkgs := make([]Pkg, 0, len(b.pkgs))

	for _, pkgInfo := range b.pkgs {
		pkgs = append(pkgs, *pkgInfo)
	}

	return pkgs
}

func (b *Builder) GetRootNode() *Node {
	return b.nodes[b.rootNodeID]
}

func (b *Builder) AddNode(nodeID string, pkgInfo *PkgInfo) *Node {
	return b.addNode(nodeID, pkgInfo)
}

func (b *Builder) addNode(nodeID string, pkgInfo *PkgInfo) *Node {
	if n, ok := b.nodes[nodeID]; ok {
		return n
	}
	pkgID := getPkgID(pkgInfo)

	b.pkgs[pkgID] = &Pkg{
		ID:   pkgID,
		Info: *pkgInfo,
	}

	b.nodes[nodeID] = &Node{
		NodeID: nodeID,
		PkgID:  pkgID,
		Deps:   make([]Dependency, 0),
	}

	return b.nodes[nodeID]
}

func (b *Builder) ConnectNodes(parentNodeID, childNodeID string) error {
	parentNode, ok := b.nodes[parentNodeID]
	if !ok {
		return fmt.Errorf("cound not find parent node %s", parentNodeID)
	}

	childNode, ok := b.nodes[childNodeID]
	if !ok {
		return fmt.Errorf("cound not find child node %s", childNodeID)
	}

	parentNode.Deps = append(parentNode.Deps, Dependency{
		NodeID: childNode.NodeID,
	})

	return nil
}

func getPkgID(pkgInfo *PkgInfo) string {
	return fmt.Sprintf("%s@%s", pkgInfo.Name, pkgInfo.Version)
}
