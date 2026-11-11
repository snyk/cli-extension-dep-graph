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
		p.withResultMetadata(&result, opts)
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
	result := ecosystems.SCAResult{Error: err}
	p.withResultMetadata(&result, opts)
	if emitErr := onGraph(result); emitErr != nil {
		return fmt.Errorf("emitting %s failure: %w", p.GetName(), emitErr)
	}
	return nil
}

func (p nativePlugin) withResultMetadata(result *ecosystems.SCAResult, opts *ecosystems.SCAPluginOptions) {
	var metadata ecosystems.ResolverMetadata
	if result.ResolverMetadata != nil {
		metadata = *result.ResolverMetadata
	}
	if metadata.PluginName == "" {
		metadata.PluginName = p.GetName()
	}
	if metadata.NormalisedTargetFile == "" {
		target := result.ProjectDescriptor.GetTargetFile()
		if target == "" && opts != nil && opts.Global.TargetFile != nil {
			target = *opts.Global.TargetFile
		}
		if target == "" {
			target = p.GetName()
		}
		metadata.NormalisedTargetFile = target
	}
	result.ResolverMetadata = &metadata
}
