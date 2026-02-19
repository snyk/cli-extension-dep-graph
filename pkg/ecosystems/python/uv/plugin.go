package uv

import (
	"context"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

type Plugin struct{}

// Compile-time check to ensure Plugin implements SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) BuildDepGraphsFromDir(_ context.Context, _ logger.Logger, _ string, _ *ecosystems.SCAPluginOptions) ([]ecosystems.SCAResult, error) {
	return nil, fmt.Errorf("not yet implemented")
}
