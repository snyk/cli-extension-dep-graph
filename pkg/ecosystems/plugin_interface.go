package ecosystems

import "context"

// PackageID uniquely identifies a package, typically in the format "name@version".
type PackageID string

// Package represents a dependency package with its identifying information.
type Package struct {
	PackageID   PackageID `json:"packageId"`
	PackageName string    `json:"packageName"`
	Version     string    `json:"version"`
}

// Depgraph represents the complete dependency graph containing all packages
// and their relationships in an adjacency list structure, with a root package
// identifier that marks the entry point of the dependency graph.
type Depgraph struct {
	Packages      map[PackageID]Package     `json:"packages"`
	Graph         map[PackageID][]PackageID `json:"graph"`
	RootPackageID PackageID                 `json:"rootPackageId"`
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
