package uv

import (
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

type Plugin struct{}

func (p Plugin) BuildDepGraphsFromDir(_ string, _ ecosystems.ScaPluginOptions) (*ecosystems.Depgraph, error) {
	return nil, fmt.Errorf("not yet implemented")
}
