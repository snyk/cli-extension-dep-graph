package scaplugin

import "github.com/rs/zerolog"

type Options struct {
	AllProjects bool
	Dev         bool
}

type Metadata struct {
	PackageManager string
	Name           string
	Version        string
}

type WorkspacePackage struct {
	Name    string
	Version string
	Path    string // Relative path to the workspace package directory
}

type Finding struct {
	Sbom                 Sbom               // The raw SBOM bytes
	Metadata             Metadata           // Information about the finding
	FileExclusions       []string           // Paths for files that other plugins should ignore
	NormalisedTargetFile string             // The target file name without any qualifiers, e.g. `uv.lock` (and not `dir/uv.lock`)
	WorkspacePackages    []WorkspacePackage // Packages that are part of a workspace
}

type Sbom []byte

type ScaPlugin interface {
	BuildFindingsFromDir(dir string, options Options, logger *zerolog.Logger) ([]Finding, error)
}
