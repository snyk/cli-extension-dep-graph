package ecosystems

import "context"

// GraphNode represents a node in the dependency graph tree structure.
// It contains a reference to its parent package and a map of child nodes.
type GraphNode struct {
	ParentPackageID *string              `json:"parentPackageId,omitempty"`
	PackageID       string               `json:"packageId"`
	Nodes           map[string]GraphNode `json:"nodes"`
}

// Package represents a dependency package with its identifying information.
type Package struct {
	PackageID   string `json:"packageId"`
	PackageName string `json:"packageName"`
	Version     string `json:"version"`
}

// Depgraph represents the complete dependency graph containing all packages
// and their relationships in a tree structure.
type Depgraph struct {
	Packages map[string]Package `json:"packages"`
	Graph    GraphNode          `json:"graph"`
}

// Metadata contains contextual information about the dependency graph,
// such as the target file and runtime environment.
type Metadata struct {
	TargetFile string `json:"targetFile"`
	Runtime    string `json:"runtime"`
}

// ScaResult represents the result of a Software Composition Analysis (SCA),
// containing the dependency graph and associated metadata.
type ScaResult struct {
	DepGraph Depgraph `json:"depGraph"`
	Metadata Metadata `json:"metadata"`
}

// ScaPlugin defines the interface for SCA plugins that build dependency graphs
// from a directory containing project files.
type ScaPlugin interface {
	BuildDepGraphsFromDir(ctx context.Context, dir string, options ScaPluginOptions) ([]ScaResult, error)
}
