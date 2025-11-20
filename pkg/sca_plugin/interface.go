package scaplugin

import "github.com/rs/zerolog"

type Options struct{}

type Finding struct {
	Sbom           Sbom
	FilesProcessed []string
	TargetFile     string
}

type Sbom []byte

type ScaPlugin interface {
	BuildFindingsFromDir(dir string, options Options, logger *zerolog.Logger) ([]Finding, error)
}
