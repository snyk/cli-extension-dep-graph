package scaplugin

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

type Options struct {
	AllProjects bool
	Dev         bool
	Exclude     []string
}

type ConversionConfig struct {
	RemoteRepoURL string
	SnykClient    *snykclient.SnykClient
}

func NewConversionConfig(remoteRepoURL string, snykClient *snykclient.SnykClient) ConversionConfig {
	return ConversionConfig{
		RemoteRepoURL: remoteRepoURL,
		SnykClient:    snykClient,
	}
}

type Metadata struct {
	PackageManager string
	Name           string
	Version        string
}

type Finding struct {
	DepGraph       *depgraph.DepGraph // The dependency graph
	FileExclusions []string           // Paths for files that other plugins should ignore
	// TODO: are the two file fields below correct?
	NormalisedTargetFile string // The lock file path relative to inputDir, e.g. `uv.lock` or `project1/uv.lock`
	TargetFileFromPlugin string // The manifest file path from the plugin, e.g. `pyproject.toml` or `project1/pyproject.toml`
	Error                error  // Error that occurred while building the finding
}

type ScaPlugin interface {
	BuildFindingsFromDir(
		ctx context.Context,
		dir string,
		options *Options,
		conversionConfig *ConversionConfig,
		logger *zerolog.Logger,
	) ([]Finding, error)
}
