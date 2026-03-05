package scaplugin

import (
	"context"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

type Options struct {
	AllProjects         bool
	UvWorkspacePackages bool
	TargetFile          string
	Dev                 bool
	Exclude             []string
	FailFast            bool
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
		log logger.Logger,
	) ([]Finding, error)
}
