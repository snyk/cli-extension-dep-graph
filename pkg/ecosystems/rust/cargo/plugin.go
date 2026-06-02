package cargo

import (
	"context"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

const (
	PluginName = "cargo"
	pkgManager = "cargo"
)

// Plugin implements ecosystems.SCAPlugin for Cargo (Rust) projects.
// It runs `cargo tree --locked` to resolve the full dependency graph without
// bespoke Cargo.lock parsing, in line with the unified-scanners principle of
// preferring native package-manager tooling. The same command runs in CLI and
// SCM surfaces with no per-environment branching.
type Plugin struct{}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir is the skeleton entry point — it currently returns no
// results. Discovery, executor, parser and dep-graph builder land in
// subsequent commits; this stub exists so the plugin can be registered behind
// FlagCargoResolver without affecting any execution path.
func (p Plugin) BuildDepGraphsFromDir(
	_ context.Context,
	_ logger.Logger,
	_ string,
	_ *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	return &ecosystems.PluginResult{}, nil
}
