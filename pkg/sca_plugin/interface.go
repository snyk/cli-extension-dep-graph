package scaplugin

import "github.com/rs/zerolog"

type Options struct{}

type Sbom []byte

type ScaPlugin interface {
	BuildSbomsFromDir(dir string, options Options, logger *zerolog.Logger) ([]Sbom, error)
}
