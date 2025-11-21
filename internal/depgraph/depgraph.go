// TODO(uv): this is copied from the `dep-graph-go` library. We should open-source that code and import it here.
package depgraph

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type (
	DepGraph struct {
		SchemaVersion string     `json:"schemaVersion"`
		PkgManager    PkgManager `json:"pkgManager"`
		Pkgs          []Pkg      `json:"pkgs"`
		Graph         Graph      `json:"graph"`

		rootPkg *Pkg            `json:"-"`
		pkgIdx  map[string]*Pkg `json:"-"`
	}

	PkgManager struct {
		Name         string       `json:"name"`
		Version      string       `json:"version,omitempty"`
		Repositories []Repository `json:"repositories,omitempty"`
	}

	Repository struct {
		Alias string `json:"alias"`
	}

	Pkg struct {
		ID   string  `json:"id"`
		Info PkgInfo `json:"info"`
	}

	PkgInfo struct {
		Name       string `json:"name"`
		Version    string `json:"version,omitempty"`
		PackageURL string `json:"purl,omitempty"`
	}

	Graph struct {
		RootNodeID string `json:"rootNodeId"`
		Nodes      []Node `json:"nodes"`
	}

	Node struct {
		NodeID string       `json:"nodeId"`
		PkgID  string       `json:"pkgId"`
		Info   *NodeInfo    `json:"info,omitempty"`
		Deps   []Dependency `json:"deps"`
	}

	NodeInfo struct {
		VersionProvenance *VersionProvenance `json:"versionProvenance,omitempty"`
		Labels            map[string]string  `json:"labels,omitempty"`
	}

	Dependency struct {
		NodeID string `json:"nodeId"`
	}

	VersionProvenance struct {
		Type     string    `json:"type"`
		Location string    `json:"location"`
		Property *Property `json:"property,omitempty"`
	}

	Property struct {
		Name string `json:"name"`
	}
)

func New() *DepGraph {
	return &DepGraph{
		Pkgs: make([]Pkg, 0),
		Graph: Graph{
			Nodes: make([]Node, 0),
		},
	}
}

func UnmarshalJSON(data []byte) (*DepGraph, error) {
	dg := new(DepGraph)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&dg); err != nil {
		return nil, fmt.Errorf("could not decode DepGraph: %w", err)
	}

	return dg, nil
}

func (dg *DepGraph) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(*dg)
	if err != nil {
		return nil, fmt.Errorf("could not encode DepGraph: %w", err)
	}
	return data, nil
}

func (dg *DepGraph) GetRootPkg() *Pkg {
	if dg.rootPkg != nil {
		return dg.rootPkg
	}

	for _, dep := range dg.Graph.Nodes {
		if dep.NodeID != dg.Graph.RootNodeID {
			continue
		}

		for _, pkg := range dg.Pkgs {
			if pkg.ID != dep.PkgID {
				continue
			}

			dg.rootPkg = &pkg
			break
		}
	}

	return dg.rootPkg
}

func (dg *DepGraph) GetPkg(id string) (*Pkg, bool) {
	if dg.pkgIdx == nil {
		dg.pkgIdx = make(map[string]*Pkg)
		for _, pkg := range dg.Pkgs {
			dg.pkgIdx[pkg.ID] = &pkg
		}
	}

	if pkg, ok := dg.pkgIdx[id]; ok {
		return pkg, ok
	}

	return nil, false
}
