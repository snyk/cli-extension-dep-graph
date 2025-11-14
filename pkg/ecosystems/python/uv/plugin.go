package uv

import (
	"context"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

type Plugin struct{}

// Compile-time check to ensure Plugin implements ScaPlugin interface.
var _ ecosystems.ScaPlugin = (*Plugin)(nil)

func (p Plugin) BuildDepGraphsFromDir(_ context.Context, _ string, _ ecosystems.ScaPluginOptions) ([]ecosystems.ScaResult, error) {
	return nil, fmt.Errorf("not yet implemented")
}
