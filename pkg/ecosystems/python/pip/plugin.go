package pip

import (
	"errors"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

type PipPlugin struct{}

func (plug PipPlugin) BuildDepGraphsFromDir(dir string, option ecosystems.ScaPluginOptions) (*ecosystems.Depgraph, error) {
	return nil, errors.New("not yet implemented")
}
