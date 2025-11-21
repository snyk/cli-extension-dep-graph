package scaplugin

import "github.com/rs/zerolog"

type Options struct{}

type Finding struct {
	Sbom                 Sbom     // The raw SBOM bytes
	FileExclusions       []string // Paths for files that other plugins should ignore
	NormalisedTargetFile string   // The target file name without any qualifiers, e.g. `uv.lock` (and not `dir/uv.lock`)
}

type Sbom []byte

type ScaPlugin interface {
	BuildFindingsFromDir(dir string, options Options, logger *zerolog.Logger) ([]Finding, error)
}
