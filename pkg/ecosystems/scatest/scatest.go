// Package scatest provides shared helpers for SCAPlugin tests across
// pkg/ecosystems/* — chiefly Run, which drives a plugin's
// BuildDepGraphsFromDir and returns every emitted SCAResult as a
// slice for the test body to inspect.
package scatest

import (
	"context"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// Run drives plugin.BuildDepGraphsFromDir and returns every emitted
// SCAResult for the test to inspect. The callback is serialized
// (single goroutine), matching the SCAPlugin concurrency contract.
func Run(
	ctx context.Context,
	plugin ecosystems.SCAPlugin,
	log logger.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
) ([]ecosystems.SCAResult, error) {
	var results []ecosystems.SCAResult
	err := plugin.BuildDepGraphsFromDir(ctx, log, dir, opts, func(r ecosystems.SCAResult) error {
		results = append(results, r)
		return nil
	})
	if err != nil {
		return results, fmt.Errorf("scatest.Run: %w", err)
	}
	return results, nil
}
