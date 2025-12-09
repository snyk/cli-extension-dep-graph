package scaplugin

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

type Options struct {
	AllProjects bool
	TargetFile  string
	Dev         bool
	Exclude     []string
}

type Metadata struct {
	PackageManager string
	Name           string
	Version        string
}

type Finding struct {
	DepGraph       *depgraph.DepGraph // The dependency graph.
	FileExclusions []string           // Paths for files that other plugins should ignore, as they (or related files) have already been processed by the plugin.
	LockFile       string             // The lock file path relative to the input directory.
	ManifestFile   string             // The manifest file path relative to the input directory.

	Error error // Error that occurred while building the finding, if any.
}

type SCAPlugin interface {
	BuildFindingsFromDir(
		ctx context.Context,
		dir string,
		options *Options,
		logger *zerolog.Logger,
	) ([]Finding, error)
}
