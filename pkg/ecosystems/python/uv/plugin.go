package uv

import (
	"errors"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

type UvPlugin struct{}

func (plug UvPlugin) BuildDepGraphsFromDir(dir string, option ecosystems.ScaPluginOptions) (*ecosystems.Depgraph, error) {
	return nil, errors.New("not yet implemented")
}
