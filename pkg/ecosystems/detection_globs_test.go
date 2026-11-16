package ecosystems_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				"App.csproj", "App.fsproj", "App.vbproj",
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

// A plugin's inputs must include the files that make it run, or a caller fetching
// only its inputs would never see them.
func TestSCAPlugin_InputGlobsIncludeTheirDetectionGlobs(t *testing.T) {
	for _, plugin := range allPlugins() {
		t.Run(plugin.GetName(), func(t *testing.T) {
			inputs := plugin.InputGlobs()
			require.NotEmpty(t, inputs)
			for _, glob := range plugin.DetectionGlobs() {
				sample := strings.ReplaceAll(glob, "*", "x")
				assert.True(t, matchesAny(inputs, sample), "inputs must include detection glob %s", glob)
			}
		})
	}
}

func TestSCAPlugin_InputGlobsNameTheFilesAPluginReads(t *testing.T) {
	for _, tt := range []struct {
		plugin  ecosystems.SCAPlugin
		claims  []string
		ignores []string
	}{
		{
			plugin: nuget.Plugin{},
			claims: []string{
				"App.csproj", "App.fsproj", "App.vbproj", "App.vcxproj", "App.sqlproj", "App.sln", "App.slnx", "App.slnf",
				"Directory.Build.props", "Directory.Build.targets", "Common.projitems", "nuget.config", "NuGet.Config",
				"global.json", "packages.lock.json", "packages.config", "Pkg.nuspec", "pkg.1.0.0.nupkg", "paket.lock",
			},
			ignores: []string{"Program.cs", "Startup.vb", "Main.fs", "README.md", "Dockerfile"},
		},
		{
			plugin:  bun.Plugin{},
			claims:  []string{"bun.lock", "bun.lockb", "package.json"},
			ignores: []string{"index.ts", "pnpm-lock.yaml", "tsconfig.json"},
		},
		{
			plugin:  pnpm.Plugin{},
			claims:  []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "rush.json", "subspaces.json"},
			ignores: []string{"index.ts", "bun.lock", "yarn.lock"},
		},
		{
			plugin:  uv.Plugin{},
			claims:  []string{"uv.lock", "pyproject.toml", "uv.toml"},
			ignores: []string{"main.py", "Pipfile.lock", "poetry.lock"},
		},
		{
			plugin:  pip.Plugin{},
			claims:  []string{"requirements.txt", "base.txt", "constraints.txt", "pyproject.toml", "setup.py", "setup.cfg"},
			ignores: []string{"main.py", "Pipfile", "uv.lock"},
		},
		{
			plugin:  pipenv.Plugin{},
			claims:  []string{"Pipfile", "Pipfile.lock"},
			ignores: []string{"requirements.txt", "pyproject.toml", "uv.lock"},
		},
		{
			plugin:  cargo.Plugin{},
			claims:  []string{"Cargo.toml", "Cargo.lock", "config.toml"},
			ignores: []string{"main.rs", "lib.rs", "go.mod"},
		},
	} {
		t.Run(tt.plugin.GetName(), func(t *testing.T) {
			globs := tt.plugin.InputGlobs()
			for _, name := range tt.claims {
				assert.True(t, matchesAny(globs, name), "must read %s", name)
			}
			for _, name := range tt.ignores {
				assert.False(t, matchesAny(globs, name), "must not read %s", name)
			}
		})
	}
}

// These plugins read files that cannot be listed, so they need the whole directory.
func TestSCAPlugin_InputGlobsAreEverythingWhenTheFilesCannotBeListed(t *testing.T) {
	for _, plugin := range []ecosystems.SCAPlugin{gradle.NewGradlePlugin(), bazel.Plugin{}, legacy.NewPlugin(nil)} {
		assert.Equal(t, []string{ecosystems.AllFilesGlob}, plugin.InputGlobs(), plugin.GetName())
		assert.True(t, matchesAny(plugin.InputGlobs(), "Source.kt"), plugin.GetName())
	}
}

func allPlugins() []ecosystems.SCAPlugin {
	return []ecosystems.SCAPlugin{
		pip.Plugin{},
		pipenv.Plugin{},
		uv.Plugin{},
		cargo.Plugin{},
		gradle.NewGradlePlugin(),
		nuget.Plugin{},
		bazel.Plugin{},
		pnpm.Plugin{},
		bun.Plugin{},
		legacy.NewPlugin(nil),
	}
}

func matchesAny(globs []string, name string) bool {
	for _, glob := range globs {
		if ok, err := filepath.Match(glob, name); err == nil && ok {
			return true
		}
	}
	return false
}
