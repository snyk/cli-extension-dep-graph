package nuget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// packagesConfigManifest is a .NET Framework manifest that needs no .csproj:
// the targetFramework attributes NuGet writes are enough to name a runtime.
const packagesConfigManifest = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="10.0.3" targetFramework="net45" />
  <package id="jQuery" version="3.2.1" targetFramework="net45" />
</packages>`

const csprojNet45 = `<Project><PropertyGroup><TargetFramework>net45</TargetFramework></PropertyGroup></Project>`

// recordingLogger captures logged messages so tests can assert on what the
// resolver reported without depending on a real logger backend.
type recordingLogger struct {
	info  []string
	debug []string
	errs  []string
}

func (r *recordingLogger) Info(_ context.Context, msg string, _ ...logger.Field) {
	r.info = append(r.info, msg)
}

func (r *recordingLogger) Debug(_ context.Context, msg string, _ ...logger.Field) {
	r.debug = append(r.debug, msg)
}

func (r *recordingLogger) Error(_ context.Context, msg string, _ ...logger.Field) {
	r.errs = append(r.errs, msg)
}

var _ logger.Logger = (*recordingLogger)(nil)

// singleTargetAssets is a valid net8.0 assets file with one direct dependency
// and one transitive one. It stands in wherever a test needs a resolvable
// project rather than a specific graph shape.
const singleTargetAssets = `{
  "version": 3,
  "targets": {
    "net8.0": {
      "Newtonsoft.Json/13.0.3": {
        "type": "package",
        "dependencies": { "System.Buffers": "4.5.1" }
      },
      "System.Buffers/4.5.1": { "type": "package" }
    }
  },
  "projectFileDependencyGroups": {
    "net8.0": [ "Newtonsoft.Json >= 13.0.3" ]
  },
  "project": {
    "version": "1.2.3",
    "restore": { "projectName": "FromAssetsFile" },
    "frameworks": { "net8.0": { "targetAlias": "net8.0" } }
  }
}`

// multiTargetAssets targets two frameworks, resolving a different version of
// the same package for each.
const multiTargetAssets = `{
  "version": 3,
  "targets": {
    "net6.0": { "Newtonsoft.Json/13.0.1": { "type": "package" } },
    "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } }
  },
  "projectFileDependencyGroups": {
    "net6.0": [ "Newtonsoft.Json >= 13.0.1" ],
    "net8.0": [ "Newtonsoft.Json >= 13.0.1" ]
  },
  "project": {
    "version": "1.0.0",
    "frameworks": {
      "net6.0": { "targetAlias": "net6.0" },
      "net8.0": { "targetAlias": "net8.0" }
    }
  }
}`

// writeFiles creates each named file (with intermediate directories) inside a
// fresh temp dir and returns that dir. Manifests and .csproj files get
// resolvable content; anything else is created empty.
func writeFiles(t *testing.T, names ...string) string {
	t.Helper()

	dir := t.TempDir()

	for _, name := range names {
		write(t, dir, name, fixtureContent(name))
	}

	return dir
}

// fixtureContent gives a fixture file whatever content makes it resolvable, so
// a test naming a file gets a real project rather than an empty one.
func fixtureContent(name string) string {
	switch base := filepath.Base(name); {
	case base == projectAssetsFile:
		return singleTargetAssets
	case base == packagesConfigFile:
		return packagesConfigManifest
	case filepath.Ext(base) == csprojExt:
		return csprojNet45
	default:
		return ""
	}
}

// write creates one file under dir, making any parent directories it needs.
func write(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

// relPaths returns the target file of every result, for order-independent comparison.
func relPaths(t *testing.T, results []ecosystems.SCAResult) []string {
	t.Helper()

	paths := make([]string, len(results))
	for i, r := range results {
		paths[i] = r.ProjectDescriptor.GetTargetFile()
	}

	return paths
}

// runtimes returns the target runtime of every result.
func runtimes(t *testing.T, results []ecosystems.SCAResult) []string {
	t.Helper()

	found := make([]string, len(results))
	for i, r := range results {
		require.NotNil(t, r.ProjectDescriptor.Identity.TargetRuntime, "result %d has no target runtime", i)
		found[i] = *r.ProjectDescriptor.Identity.TargetRuntime
	}

	return found
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "dotnet", Plugin{}.GetName())
}

func TestPlugin_RootDirOnly(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile, "nested/"+projectAssetsFile)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "without --all-projects only the scanned root is inspected")

	result := results[0]
	require.NoError(t, result.Error)
	require.NotNil(t, result.DepGraph)
	assert.Equal(t, projectAssetsFile, result.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, filepath.Base(dir), result.ProjectDescriptor.Identity.RootComponentName)
	assert.Equal(t, pkgManager, result.ProjectDescriptor.Identity.ProjectType)

	// The target framework comes from the assets file rather than a placeholder.
	require.NotNil(t, result.ProjectDescriptor.Identity.TargetRuntime)
	assert.Equal(t, "net8.0", *result.ProjectDescriptor.Identity.TargetRuntime)

	require.NotNil(t, result.ResolverMetadata)
	assert.Equal(t, PluginName, result.ResolverMetadata.PluginName)
	assert.Equal(t, projectAssetsFile, result.ResolverMetadata.NormalisedTargetFile)
}

// Restore output lives in obj/, and detect.ts allows that path explicitly, so a
// default scan of an SDK-style project must still find it.
func TestPlugin_RootDirOnly_FindsProjectAssetsInObj(t *testing.T) {
	dir := writeFiles(t, filepath.Join(objDir, projectAssetsFile))

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, filepath.Join(objDir, projectAssetsFile), results[0].ProjectDescriptor.GetTargetFile())
	assert.Equal(t, filepath.Base(dir), results[0].ProjectDescriptor.Identity.RootComponentName)
}

// Project files are not discoverable target files: snyk-nuget-plugin reads them
// internally, but the CLI keys discovery on restore output and config files.
func TestPlugin_ProjectFilesAreNotTargetFiles(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj", "MyApp.vbproj", "MyApp.fsproj", "MySolution.sln")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithAllProjects(true))
	require.NoError(t, err)
	assert.Empty(t, results)
}

// A packages.config resolves without a .csproj: NuGet writes a targetFramework
// onto every entry it installs, and that is enough to name a runtime.
func TestPlugin_PackagesConfigResolves(t *testing.T) {
	dir := writeFiles(t, packagesConfigFile)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "this manifest records one dependency set, so there is one result")

	result := results[0]
	require.NoError(t, result.Error)
	require.NotNil(t, result.DepGraph)
	assert.Equal(t, packagesConfigFile, result.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, filepath.Base(dir), result.ProjectDescriptor.Identity.RootComponentName)
	assert.Equal(t, pkgManager, result.ProjectDescriptor.Identity.ProjectType)
	assert.Equal(t, []string{"net45"}, runtimes(t, results))

	// Resolving it means claiming it, which is what stops the legacy resolver
	// reporting the same project a second time.
	assert.Equal(t, []string{packagesConfigFile}, result.ProcessedFiles)

	assert.ElementsMatch(t,
		[]string{result.DepGraph.GetRootPkg().ID, "Newtonsoft.Json@10.0.3", "jQuery@3.2.1"},
		pkgIDs(result.DepGraph.Pkgs))
}

// project.json is a .NET manifest the CLI discovers, but this resolver does not
// handle it yet. Reporting nothing is what hands it back to the legacy
// resolver — including for a single project, where the workflow only moves on
// to the next plugin because this one returned no results at all.
func TestPlugin_ProjectJSONIsLeftToLegacy(t *testing.T) {
	dir := writeFiles(t, projectJSONFile)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err, "an unsupported .NET manifest is not an error")
	assert.Empty(t, results)

	results, err = scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithTargetFile(projectJSONFile))
	require.NoError(t, err, "nor is one named explicitly with --file")
	assert.Empty(t, results)
}

// Nothing names a framework for this project, and a .NET project has to have
// one. Guessing would report it under a framework it does not target, so it
// goes to the legacy resolver instead — which fails on it exactly as it does
// today.
func TestPlugin_ManifestWithNoTargetFrameworkIsLeftToLegacy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, packagesConfigFile, `<packages><package id="Newtonsoft.Json" version="10.0.3" /></packages>`)

	log := &recordingLogger{}
	results, err := scatest.Run(context.Background(), Plugin{}, log, dir, ecosystems.NewPluginOptions())

	require.NoError(t, err, "one unresolvable project must not end a scan of many")
	assert.Empty(t, results)
	assert.NotEmpty(t, log.errs, "the reason is logged, not swallowed")
}

func TestPlugin_UnreadableManifestIsLeftToLegacy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, packagesConfigFile, `<configuration><package id="X" version="1.0" /></configuration>`)
	write(t, dir, "App.csproj", csprojNet45)

	log := &recordingLogger{}
	results, err := scatest.Run(context.Background(), Plugin{}, log, dir, ecosystems.NewPluginOptions())

	require.NoError(t, err)
	assert.Empty(t, results, "claiming a manifest we could not read would hide it from the resolver that can")
	assert.NotEmpty(t, log.errs)
}

func TestPlugin_DepGraphShape(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	graph := results[0].DepGraph
	require.NotNil(t, graph)
	assert.Equal(t, pkgManager, graph.PkgManager.Name)
	assert.Equal(t, filepath.Base(dir), graph.GetRootPkg().Info.Name)
	assert.Equal(t, "1.2.3", graph.GetRootPkg().Info.Version, "the root version comes from project.version")

	assert.ElementsMatch(t,
		[]string{graph.GetRootPkg().ID, "Newtonsoft.Json@13.0.3", "System.Buffers@4.5.1"},
		pkgIDs(graph.Pkgs))
}

// Real resolution means claiming the file, which is what stops the legacy
// resolver reporting the same project a second time.
func TestPlugin_ClaimsProcessedFiles(t *testing.T) {
	dir := writeFiles(t, filepath.Join(objDir, projectAssetsFile))

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, []string{filepath.Join(objDir, projectAssetsFile)}, results[0].ProcessedFiles)
}

// A project can target several frameworks, and each resolves to its own
// dependency set. The results are distinguished only by target runtime.
func TestPlugin_MultiTargetEmitsOneResultPerFramework(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, filepath.Join(objDir, projectAssetsFile), multiTargetAssets)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, []string{"net6.0", "net8.0"}, runtimes(t, results),
		"frameworks are reported in the order the assets file declares them")

	for _, result := range results {
		require.NoError(t, result.Error)
		assert.Equal(t, filepath.Join(objDir, projectAssetsFile), result.ProjectDescriptor.GetTargetFile())
		assert.Equal(t, filepath.Base(dir), result.ProjectDescriptor.Identity.RootComponentName)
	}

	assert.Contains(t, pkgIDs(results[0].DepGraph.Pkgs), "Newtonsoft.Json@13.0.1")
	assert.Contains(t, pkgIDs(results[1].DepGraph.Pkgs), "Newtonsoft.Json@13.0.3")
}

// An assets file this resolver cannot use is left to the legacy resolver: no
// result and no claim, so the project is still scanned by something. Emitting an
// error result instead would fail the whole scan under the dep-graph workflow
// and discard every other plugin's graphs under the orchestrator.
func TestPlugin_UnusableAssetsFileIsLeftToLegacy(t *testing.T) {
	tests := map[string]string{
		"not json":           `{ not json`,
		"no project section": `{"version":3,"targets":{"net8.0":{}}}`,
		"no frameworks":      `{"version":3,"targets":{"net8.0":{}},"project":{"version":"1.0.0"}}`,
		"no targets":         `{"version":3,"project":{"frameworks":{"net8.0":{}}}}`,
	}

	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, projectAssetsFile, content)

			log := &recordingLogger{}

			results, err := scatest.Run(context.Background(), Plugin{}, log, dir, ecosystems.NewPluginOptions())
			require.NoError(t, err, "an unusable assets file is not a returned error")
			assert.Empty(t, results, "nothing is reported, so the legacy resolver still runs")
			assert.NotEmpty(t, log.errs, "but the user is told why we skipped it")
		})
	}
}

// A restore that wrote the section but not its contents leaves a framework that
// cannot resolve. That is reported against the framework, not deferred: the
// runtime is known, so the project has an identity to attach the failure to.
func TestPlugin_DeclaredFrameworkThatCannotResolveIsReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, projectAssetsFile, `{
      "version": 3,
      "targets": { "net8.0": null },
      "projectFileDependencyGroups": { "net8.0": [ "Newtonsoft.Json >= 13.0.3" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": { "targetAlias": "net8.0" } } }
    }`)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	require.Error(t, results[0].Error)
	assert.Nil(t, results[0].DepGraph)

	require.NotNil(t, results[0].ProjectDescriptor.Identity.TargetRuntime)
	assert.Equal(t, "net8.0", *results[0].ProjectDescriptor.Identity.TargetRuntime)
}

// Every emitted result carries a target runtime, including the ones that failed.
func TestPlugin_EveryResultCarriesATargetRuntime(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, projectAssetsFile, multiTargetAssets)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.NotEmpty(t, results)

	for _, result := range results {
		require.NotNil(t, result.ProjectDescriptor.Identity.TargetRuntime)
		assert.NotEmpty(t, *result.ProjectDescriptor.Identity.TargetRuntime)
	}
}

// A project we skipped must not be excluded from the resolver that could still
// handle it, which is what claiming the file would do.
func TestPlugin_UnusableAssetsFileClaimsNothing(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, filepath.Join("Broken", objDir, projectAssetsFile), "{ not json")
	write(t, dir, filepath.Join("Healthy", objDir, projectAssetsFile), singleTargetAssets)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithAllProjects(true))
	require.NoError(t, err)

	// The healthy project resolves and is claimed; the broken one is absent
	// entirely, so nothing downstream is told to skip it.
	require.Len(t, results, 1)
	assert.Equal(t, "Healthy", results[0].ProjectDescriptor.Identity.RootComponentName)
	assert.Equal(t, []string{filepath.Join("Healthy", objDir, projectAssetsFile)}, results[0].ProcessedFiles)
}

// A multi-target project mixing the pre-net5 families resolves each framework
// against its own packages. Every one of those long monikers is derived from the
// short one, so none of them needs the positional fallback.
func TestPlugin_MixedLegacyFrameworksEachResolveTheirOwn(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, projectAssetsFile, `{
      "version": 3,
      "targets": {
        ".NETCoreApp,Version=v3.1": { "Newtonsoft.Json/13.0.3": { "type": "package" } },
        ".NETFramework,Version=v4.7.2": { "Humanizer/2.14.1": { "type": "package" } }
      },
      "projectFileDependencyGroups": {
        ".NETCoreApp,Version=v3.1": [ "Newtonsoft.Json >= 13.0.3" ],
        ".NETFramework,Version=v4.7.2": [ "Humanizer >= 2.14.1" ]
      },
      "project": {
        "version": "1.0.0",
        "frameworks": { "netcoreapp3.1": {}, "net472": {} }
      }
    }`)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, []string{"netcoreapp3.1", "net472"}, runtimes(t, results),
		"reported as the project declares them, not as the targets section spells them")
	assert.Contains(t, pkgIDs(results[0].DepGraph.Pkgs), "Newtonsoft.Json@13.0.3")
	assert.Contains(t, pkgIDs(results[1].DepGraph.Pkgs), "Humanizer@2.14.1")
}

// A framework whose moniker no rule derives and no prefix matches is reported as
// a failure, not dropped: the runtime is part of a project's identity, so a
// declared framework has to be accounted for either way. Its siblings still
// resolve — guessing one of theirs would report the wrong dependencies here.
func TestPlugin_UnmatchableFrameworkIsReportedNotGuessed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, projectAssetsFile, `{
      "version": 3,
      "targets": {
        "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } },
        "some-vendor-moniker": { "Humanizer/2.14.1": { "type": "package" } }
      },
      "projectFileDependencyGroups": {
        "net8.0": [ "Newtonsoft.Json >= 13.0.3" ],
        "some-vendor-moniker": [ "Humanizer >= 2.14.1" ]
      },
      "project": {
        "version": "1.0.0",
        "frameworks": { "net8.0": { "targetAlias": "net8.0" }, "another-vendor-moniker": {} }
      }
    }`)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 2, "both declared frameworks are accounted for")

	byRuntime := map[string]ecosystems.SCAResult{}
	for _, result := range results {
		require.NotNil(t, result.ProjectDescriptor.Identity.TargetRuntime)
		byRuntime[*result.ProjectDescriptor.Identity.TargetRuntime] = result
	}

	resolved := byRuntime["net8.0"]
	require.NoError(t, resolved.Error)
	assert.Contains(t, pkgIDs(resolved.DepGraph.Pkgs), "Newtonsoft.Json@13.0.3")

	// Reported as a failure rather than dropped, and still carrying the runtime
	// that identifies it.
	failed := byRuntime["another-vendor-moniker"]
	require.Error(t, failed.Error)
	assert.Nil(t, failed.DepGraph)
	assert.Contains(t, detailOf(t, failed.Error), "another-vendor-moniker")
}

func TestPlugin_NoTargetFiles(t *testing.T) {
	dir := writeFiles(t, "README.md", "src/main.go")
	log := &recordingLogger{}

	results, err := scatest.Run(context.Background(), Plugin{}, log, dir, ecosystems.NewPluginOptions())
	require.NoError(t, err, "a directory with no .NET projects is not an error")
	assert.Empty(t, results, "no results are emitted")
	assert.Empty(t, log.errs, "and nothing is reported as a failure")
	assert.Contains(t, strings.Join(log.debug, "\n"), "No .NET target files found")
}

func TestPlugin_NilLoggerAndNilOptions(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile)

	results, err := scatest.Run(context.Background(), Plugin{}, nil, dir, nil)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestPlugin_AllProjects(t *testing.T) {
	dir := writeFiles(t,
		"src/App/"+objDir+"/"+projectAssetsFile,
		"src/Lib/"+objDir+"/"+projectAssetsFile,
		"src/Legacy/"+packagesConfigFile,
		// Not target files, or not reachable.
		"src/App/App.csproj",
		"src/Old/"+projectJSONFile,
		"MySolution.sln",
		"paket.dependencies",
		"node_modules/pkg/"+projectAssetsFile,
		".build/"+projectAssetsFile,
	)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)

	// obj/ is deliberately not pruned: the CLI ignores only node_modules and
	// .build (src/lib/find-files.ts:55), so restore output stays discoverable.
	assert.ElementsMatch(t, []string{
		filepath.Join("src", "App", objDir, projectAssetsFile),
		filepath.Join("src", "Lib", objDir, projectAssetsFile),
		filepath.Join("src", "Legacy", packagesConfigFile),
	}, relPaths(t, results))
}

// paket.dependencies is a .NET target file, but detect.ts routes it to a
// separate paket plugin rather than to nuget.
func TestPlugin_PaketIsNotOurs(t *testing.T) {
	dir := writeFiles(t, "paket.dependencies")

	opts := ecosystems.NewPluginOptions().WithTargetFile("paket.dependencies")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_AllProjects_HonoursExcludes(t *testing.T) {
	dir := writeFiles(t, "Keep/"+projectAssetsFile, "Skip/"+projectAssetsFile)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true).WithExclude([]string{"Skip"})

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join("Keep", projectAssetsFile)}, relPaths(t, results))
}

func TestPlugin_AllProjects_HonoursExcludePaths(t *testing.T) {
	dir := writeFiles(t, "Keep/"+projectAssetsFile, "Skip/"+projectAssetsFile)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true).WithExcludePaths([]string{"Skip"})

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join("Keep", projectAssetsFile)}, relPaths(t, results))
}

func TestPlugin_TargetFile(t *testing.T) {
	dir := writeFiles(t, "a/"+projectAssetsFile, "b/"+projectAssetsFile)

	target := filepath.Join("b", projectAssetsFile)
	opts := ecosystems.NewPluginOptions().WithTargetFile(target)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, target, results[0].ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "b", results[0].ProjectDescriptor.Identity.RootComponentName)
}

// A --file pointing straight at restore output must keep working: that is how
// the CLI's current static analysis is invoked.
func TestPlugin_TargetFile_ProjectAssetsInObj(t *testing.T) {
	dir := writeFiles(t, "src/App/"+objDir+"/"+projectAssetsFile)

	target := filepath.Join("src", "App", objDir, projectAssetsFile)
	opts := ecosystems.NewPluginOptions().WithTargetFile(target)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, target, results[0].ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "App", results[0].ProjectDescriptor.Identity.RootComponentName,
		"obj/ is a build artifact directory, so the project is named one level up")
}

// An assets file directly in the scanned root has no relative directory to be
// named after, so the name comes from the root directory itself.
func TestPlugin_TargetFile_InScannedRoot(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile)

	opts := ecosystems.NewPluginOptions().WithTargetFile(projectAssetsFile)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, filepath.Base(dir), results[0].ProjectDescriptor.Identity.RootComponentName)
}

func TestPlugin_TargetFile_UnsupportedIsSkipped(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile, "package.json")

	opts := ecosystems.NewPluginOptions().WithTargetFile("package.json")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err, "another ecosystem's target file is not this plugin's concern")
	assert.Empty(t, results)
}

func TestPlugin_TargetFile_MissingReturnsError(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile)

	opts := ecosystems.NewPluginOptions().WithTargetFile("Absent/" + projectAssetsFile)

	_, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.Error(t, err, "an explicitly requested target file that does not exist is a setup failure")
}

// A non-nil onGraph error aborts the run and reaches the caller unchanged.
func TestPlugin_OnGraphErrorAbortsRun(t *testing.T) {
	dir := writeFiles(t, "a/"+projectAssetsFile, "b/"+projectAssetsFile)

	sentinel := errors.New("consumer failed")
	calls := 0

	err := Plugin{}.BuildDepGraphsFromDir(
		context.Background(),
		logger.Nop(),
		dir,
		ecosystems.NewPluginOptions().WithAllProjects(true),
		func(ecosystems.SCAResult) error {
			calls++
			return sentinel
		},
	)

	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls, "the run stops at the first callback error")
}

func TestIsSupportedTargetFile(t *testing.T) {
	tests := map[string]bool{
		"project.assets.json":         true,
		"obj/project.assets.json":     true,
		"src/App/project.assets.json": true,
		"packages.config":             true,
		"src/Legacy/packages.config":  true,
		// Discovered by the CLI, but not resolved here yet: CMPA-717.
		"project.json": false,
		// Project files are read by snyk-nuget-plugin, never discovered as targets.
		"MyApp.csproj":   false,
		"MyApp.vbproj":   false,
		"MyApp.fsproj":   false,
		"MySolution.sln": false,
		// Belongs to the paket plugin.
		"paket.dependencies": false,
		// Other ecosystems.
		"package.json":          false,
		"Directory.Build.props": false,
		"":                      false,
	}

	for path, want := range tests {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, want, isSupportedTargetFile(path))
		})
	}
}

// The dep-graph workflow passes "." when no input directory is configured,
// which is the most common CLI invocation. A relative path must still yield a
// real project name rather than ".".
func TestPlugin_RootDirOnly_RelativeDirYieldsRealName(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile)
	t.Chdir(dir)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), ".", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, filepath.Base(dir), results[0].ProjectDescriptor.Identity.RootComponentName)
	assert.Equal(t, projectAssetsFile, results[0].ProjectDescriptor.GetTargetFile())
}

func TestRootComponentName(t *testing.T) {
	sep := string(filepath.Separator)

	tests := map[string]struct {
		path string
		want string
	}{
		"names the containing directory": {
			path: filepath.Join(sep, "work", "MyApp", projectAssetsFile),
			want: "MyApp",
		},
		"steps over obj": {
			path: filepath.Join(sep, "work", "MyApp", objDir, projectAssetsFile),
			want: "MyApp",
		},
		"steps over obj case-insensitively": {
			path: filepath.Join(sep, "work", "MyApp", "OBJ", projectAssetsFile),
			want: "MyApp",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, rootComponentName(discovery.FindResult{Path: tt.path}))
		})
	}
}

// Every emitted result must carry a target runtime, so the constructor cannot be
// called without one.
func TestNewProjectIdentity_SetsEveryField(t *testing.T) {
	id := newProjectIdentity("src/App/"+projectAssetsFile, "net8.0", "App")

	require.NotNil(t, id.TargetRuntime)
	assert.Equal(t, "net8.0", *id.TargetRuntime)
	require.NotNil(t, id.TargetFile)
	assert.Equal(t, "src/App/"+projectAssetsFile, *id.TargetFile)
	assert.Equal(t, "App", id.RootComponentName)
	assert.Equal(t, pkgManager, id.ProjectType)
}

// A directory holding both a root-level assets file and restore output in obj/
// is one project, not two. The CLI picks the first hit in DETECTABLE_FILES
// order, and a scan without --all-projects still emits every result a plugin
// produces — so returning both would double-report the project.
func TestPlugin_RootDirOnly_ManifestPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		present []string
		want    string
	}{
		{
			name:    "restore output outranks the manifests beside it",
			present: []string{objDir + "/" + projectAssetsFile, projectAssetsFile, packagesConfigFile},
			want:    filepath.Join(objDir, projectAssetsFile),
		},
		{
			name:    "a root-level assets file outranks packages.config",
			present: []string{projectAssetsFile, packagesConfigFile},
			want:    projectAssetsFile,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := writeFiles(t, test.present...)

			results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Equal(t, test.want, results[0].ProjectDescriptor.GetTargetFile())
		})
	}
}

// --all-projects has no such precedence: every manifest is its own project,
// which is what the CLI reports too.
func TestPlugin_AllProjects_ReportsEveryManifestInADirectory(t *testing.T) {
	dir := writeFiles(t, objDir+"/"+projectAssetsFile, packagesConfigFile)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithAllProjects(true))
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{filepath.Join(objDir, projectAssetsFile), packagesConfigFile},
		relPaths(t, results))
}

// A scanned root that is not there at all is a setup failure, the same as a
// --file naming a path that does not exist. Reporting no target files instead
// would send the scan on to the next plugin to rediscover the same problem.
func TestPlugin_MissingScanRootIsAnError(t *testing.T) {
	_, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(),
		filepath.Join(t.TempDir(), "absent"), ecosystems.NewPluginOptions())

	require.Error(t, err)
}

// An unrestored project has no obj/, which is ordinary rather than a failure.
func TestPlugin_MissingObjDirIsNotAnError(t *testing.T) {
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), t.TempDir(), ecosystems.NewPluginOptions())

	require.NoError(t, err)
	assert.Empty(t, results)
}

// obj/ is where restore output lives, but a project is not required to have
// one — and something else occupying the name must not take the scan down with
// it. A returned error would reach the orchestrator as a failed result.
func TestPlugin_UnreadableObjDirIsNotAnError(t *testing.T) {
	dir := writeFiles(t, projectAssetsFile)
	write(t, dir, objDir, "a regular file, not a directory")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, projectAssetsFile, results[0].ProjectDescriptor.GetTargetFile())
}

// The packages folder changes what is reported, in both directions: a .nuspec
// contributes a package the manifest never lists, and an installed version
// overrides the one the manifest asked for. The default location is the
// manifest's grandparent, which is the classic solution layout.
func TestPlugin_PackagesFolderChangesTheReportedSet(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "Solution", "Project")
	packages := filepath.Join(root, "Solution", packagesFolderName)

	write(t, project, packagesConfigFile, `<packages>
  <package id="Swagger.Net" version="0.5.5" targetFramework="net45" />
  <package id="jQuery" version="1.9.1" targetFramework="net45" />
</packages>`)

	writeNupkg(t, packages, declaredPackage{"Swagger.Net", "0.5.5"},
		zipEntry{"Swagger.Net" + nuspecExt, []byte(swaggerNuspec)})
	makePackageDirs(t, packages, "jQuery.3.2.1")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), project, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	graph := results[0].DepGraph
	require.NotNil(t, graph)

	assert.ElementsMatch(t, []string{
		graph.GetRootPkg().ID,
		"Swagger.Net@0.5.5",
		// Declared as 1.9.1; 3.2.1 is what is installed, and what would
		// actually be exploited.
		"jQuery@3.2.1",
		// Named by no manifest, only by Swagger.Net's .nuspec.
		"WebActivator@1.5.1",
	}, pkgIDs(graph.Pkgs))

	assert.Equal(t, []string{"WebActivator@1.5.1"}, depsOf(t, graph, "Swagger.Net@0.5.5"))
}

// A packages folder beside the manifest rather than above it is invisible to
// the derived default, which is why --packages-folder exists. snyk/cli's own
// end-to-end test for this shape passes the flag for the same reason.
func TestPlugin_PackagesFolderFlag(t *testing.T) {
	project := t.TempDir()
	packages := filepath.Join(project, packagesFolderName)

	write(t, project, packagesConfigFile,
		`<packages><package id="Swagger.Net" version="0.5.5" targetFramework="net45" /></packages>`)
	writeNupkg(t, packages, declaredPackage{"Swagger.Net", "0.5.5"},
		zipEntry{"Swagger.Net" + nuspecExt, []byte(swaggerNuspec)})

	withoutFlag, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), project, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, withoutFlag, 1)
	assert.NotContains(t, pkgIDs(withoutFlag[0].DepGraph.Pkgs), "WebActivator@1.5.1")

	withFlag, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), project,
		ecosystems.NewPluginOptions().WithPackagesFolder(packages))
	require.NoError(t, err)
	require.Len(t, withFlag, 1)
	assert.Contains(t, pkgIDs(withFlag[0].DepGraph.Pkgs), "WebActivator@1.5.1")
}

// A truncated archive means we cannot know what that package pulls in, and
// reporting the project anyway would claim the manifest while quietly omitting
// them. The legacy resolver gets it instead.
func TestPlugin_UnreadableNupkgIsLeftToLegacy(t *testing.T) {
	project := t.TempDir()
	packages := filepath.Join(project, packagesFolderName)

	write(t, project, packagesConfigFile,
		`<packages><package id="Swagger.Net" version="0.5.5" targetFramework="net45" /></packages>`)
	write(t, filepath.Join(packages, "Swagger.Net.0.5.5"), "Swagger.Net.0.5.5"+nupkgExt, "not a zip")

	log := &recordingLogger{}
	results, err := scatest.Run(context.Background(), Plugin{}, log, project,
		ecosystems.NewPluginOptions().WithPackagesFolder(packages))

	require.NoError(t, err)
	assert.Empty(t, results)
	assert.NotEmpty(t, log.errs)
}
