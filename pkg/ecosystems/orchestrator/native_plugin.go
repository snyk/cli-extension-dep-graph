package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// Native resolver failures belong to their results so mixed scans can continue.
type nativePlugin struct {
	ecosystems.SCAPlugin
}

func (p nativePlugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	var callbackErr error
	err := p.SCAPlugin.BuildDepGraphsFromDir(ctx, log, dir, opts, func(result ecosystems.SCAResult) error {
		if callbackErr != nil {
			return callbackErr
		}
		callbackErr = onGraph(result)
		return callbackErr
	})
	if callbackErr != nil {
		return fmt.Errorf("emitting %s result: %w", p.GetName(), callbackErr)
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("running %s plugin: %w", p.GetName(), err)
	}
	target := p.GetName()
	if opts != nil && opts.Global.TargetFile != nil {
		target = *opts.Global.TargetFile
	}
	if emitErr := onGraph(ecosystems.SCAResult{
		Error: err,
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           p.GetName(),
			NormalisedTargetFile: target,
		},
	}); emitErr != nil {
		return fmt.Errorf("emitting %s failure: %w", p.GetName(), emitErr)
	}
	return nil
}
