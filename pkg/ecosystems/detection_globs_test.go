package ecosystems_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/bazel"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/dotnet/nuget"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/gradle"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/bun"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/pnpm"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/pipenv"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/uv"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/rust/cargo"
)

// A caller holding only a file listing uses DetectionGlobs to tell which plugins should
// run. Each plugin must claim the files that indicate it and none of another
// ecosystem's.
func TestSCAPlugin_DetectionGlobsClaimOnlyTheirOwnFiles(t *testing.T) {
	for _, tt := range []struct {
		plugin  ecosystems.SCAPlugin
		claims  []string
		ignores []string
	}{
		{plugin: pip.Plugin{}, claims: []string{"requirements.txt"}, ignores: []string{"Pipfile", "uv.lock"}},
		{plugin: pipenv.Plugin{}, claims: []string{"Pipfile", "Pipfile.lock"}, ignores: []string{"requirements.txt", "uv.lock"}},
		{plugin: uv.Plugin{}, claims: []string{"uv.lock"}, ignores: []string{"requirements.txt", "Pipfile"}},
		{plugin: cargo.Plugin{}, claims: []string{"Cargo.toml", "Cargo.lock"}, ignores: []string{"go.mod", "uv.lock"}},
		{
			plugin:  gradle.NewGradlePlugin(),
			claims:  []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"},
			ignores: []string{"pom.xml", "Cargo.lock"},
		},
		{
			// Project files count although nuget reads only restore output: a
			// restore turns them into what it reads.
			plugin: nuget.Plugin{},
			claims: []string{
				"App.csproj", "App.fsproj", "App.vbproj", "App.sln", "App.slnx",
				"dirs.proj", "Directory.Packages.props", "Directory.Build.props",
				"project.assets.json", "packages.config", "project.json",
			},
			ignores: []string{"package.json", "pom.xml"},
		},
		{
			plugin:  bazel.Plugin{},
			claims:  []string{"MODULE.bazel", "REPO.bazel", "WORKSPACE", "WORKSPACE.bazel"},
			ignores: []string{"go.mod", "Cargo.lock"},
		},
		{
			plugin:  pnpm.Plugin{},
			claims:  []string{"pnpm-lock.yaml", "pnpm-workspace.yaml", "rush.json"},
			ignores: []string{"package.json", "bun.lock"},
		},
		{plugin: bun.Plugin{}, claims: []string{"bun.lock", "bun.lockb"}, ignores: []string{"package.json", "pnpm-lock.yaml"}},
	} {
		t.Run(tt.plugin.GetName(), func(t *testing.T) {
			globs := tt.plugin.DetectionGlobs()
			for _, name := range tt.claims {
				assert.True(t, matchesAny(globs, name), "must claim %s", name)
			}
			for _, name := range tt.ignores {
				assert.False(t, matchesAny(globs, name), "must not claim %s", name)
			}
		})
	}
}

// The legacy CLI detects every ecosystem itself, so no file listing can rule it out.
func TestSCAPlugin_DetectionGlobsAreNilForTheLegacyCLI(t *testing.T) {
	assert.Nil(t, legacy.NewPlugin(nil).DetectionGlobs())
}

func matchesAny(globs []string, name string) bool {
	for _, glob := range globs {
		if ok, err := filepath.Match(glob, name); err == nil && ok {
			return true
		}
	}
	return false
}
