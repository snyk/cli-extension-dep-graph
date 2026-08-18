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
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// recordingLogger captures logged messages so tests can assert on the
// placeholder warning without depending on a real logger backend.
type recordingLogger struct {
	info  []string
	debug []string
}

func (r *recordingLogger) Info(_ context.Context, msg string, _ ...logger.Field) {
	r.info = append(r.info, msg)
}

func (r *recordingLogger) Debug(_ context.Context, msg string, _ ...logger.Field) {
	r.debug = append(r.debug, msg)
}

func (r *recordingLogger) Error(_ context.Context, _ string, _ ...logger.Field) {}

var _ logger.Logger = (*recordingLogger)(nil)

// writeFiles creates each named file (with intermediate directories) inside a
// fresh temp dir and returns that dir.
func writeFiles(t *testing.T, names ...string) string {
	t.Helper()

	dir := t.TempDir()

	for _, name := range names {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(""), 0o600))
	}

	return dir
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

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "dotnet", Plugin{}.GetName())
}

func TestPlugin_RootDirOnly(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj", "nested/Other.csproj")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "without --all-projects only the scanned root is inspected")

	result := results[0]
	require.NoError(t, result.Error)
	require.NotNil(t, result.DepGraph)
	assert.Equal(t, "MyApp.csproj", result.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "MyApp", result.ProjectDescriptor.Identity.RootComponentName)
	assert.Equal(t, pkgManager, result.ProjectDescriptor.Identity.ProjectType)

	require.NotNil(t, result.ResolverMetadata)
	assert.Equal(t, PluginName, result.ResolverMetadata.PluginName)
	assert.Equal(t, "MyApp.csproj", result.ResolverMetadata.NormalisedTargetFile)
}

func TestPlugin_EmptyDepGraphShape(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	graph := results[0].DepGraph
	require.NotNil(t, graph)
	assert.Equal(t, pkgManager, graph.PkgManager.Name)
	assert.Equal(t, "MyApp", graph.GetRootPkg().Info.Name)
	assert.Equal(t, defaultVersion, graph.GetRootPkg().Info.Version)
	assert.Len(t, graph.Pkgs, 1, "the placeholder graph holds the root package only")
	require.Len(t, graph.Graph.Nodes, 1)
	assert.Empty(t, graph.Graph.Nodes[0].Deps, "the placeholder graph has no dependencies")
}

func TestPlugin_DoesNotClaimProcessedFiles(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Until real resolution lands, the legacy resolver must still scan these
	// files — claiming them here would suppress a project's only real results.
	assert.Empty(t, results[0].ProcessedFiles)
}

func TestPlugin_LogsPlaceholderWarningPerTargetFile(t *testing.T) {
	dir := writeFiles(t, "A.csproj", "B.csproj")
	log := &recordingLogger{}

	results, err := scatest.Run(context.Background(), Plugin{}, log, dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 2)

	require.Len(t, log.info, 2, "one warning per discovered target file")
	for _, msg := range log.info {
		assert.Contains(t, msg, "not yet implemented")
	}
}

func TestPlugin_NoTargetFiles(t *testing.T) {
	dir := writeFiles(t, "README.md", "src/main.go")
	log := &recordingLogger{}

	results, err := scatest.Run(context.Background(), Plugin{}, log, dir, ecosystems.NewPluginOptions())
	require.NoError(t, err, "a directory with no .NET projects is not an error")
	assert.Empty(t, results, "no results are emitted")
	assert.Empty(t, log.info, "and nothing is reported to the user")
	assert.Contains(t, strings.Join(log.debug, "\n"), "No .NET target files found")
}

func TestPlugin_NilLoggerAndNilOptions(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj")

	results, err := scatest.Run(context.Background(), Plugin{}, nil, dir, nil)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestPlugin_AllProjects(t *testing.T) {
	dir := writeFiles(t,
		"MySolution.sln",
		"src/App/App.csproj",
		"src/Lib/Lib.fsproj",
		"src/Legacy/Legacy.vbproj",
		"src/Legacy/packages.config",
		// Excluded: build output and restore artifacts, vendored trees, and
		// unrelated files.
		"src/App/bin/Debug/Ignored.csproj",
		"src/App/obj/project.assets.json",
		"node_modules/pkg/Vendored.csproj",
		"src/App/App.cs",
	)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)

	// obj/ and bin/ are skipped, so src/App is reported once — via its
	// App.csproj — rather than twice via its restore output.
	assert.ElementsMatch(t, []string{
		"MySolution.sln",
		filepath.Join("src", "App", "App.csproj"),
		filepath.Join("src", "Lib", "Lib.fsproj"),
		filepath.Join("src", "Legacy", "Legacy.vbproj"),
		filepath.Join("src", "Legacy", "packages.config"),
	}, relPaths(t, results))
}

func TestPlugin_AllProjects_HonoursExcludes(t *testing.T) {
	dir := writeFiles(t, "Keep/Keep.csproj", "Skip/Skip.csproj")

	opts := ecosystems.NewPluginOptions().WithAllProjects(true).WithExclude([]string{"Skip"})

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join("Keep", "Keep.csproj")}, relPaths(t, results))
}

func TestPlugin_AllProjects_HonoursExcludePaths(t *testing.T) {
	dir := writeFiles(t, "Keep/Keep.csproj", "Skip/Skip.csproj")

	opts := ecosystems.NewPluginOptions().WithAllProjects(true).WithExcludePaths([]string{"Skip"})

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join("Keep", "Keep.csproj")}, relPaths(t, results))
}

func TestPlugin_TargetFile(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj", "Other.csproj")

	opts := ecosystems.NewPluginOptions().WithTargetFile("Other.csproj")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Other.csproj", results[0].ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "Other", results[0].ProjectDescriptor.Identity.RootComponentName)
}

// A --file pointing straight at restore output must keep working: that is how
// the CLI's current static analysis is invoked.
func TestPlugin_TargetFile_ProjectAssetsInObj(t *testing.T) {
	dir := writeFiles(t, "src/App/obj/project.assets.json")

	target := filepath.Join("src", "App", "obj", "project.assets.json")
	opts := ecosystems.NewPluginOptions().WithTargetFile(target)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, target, results[0].ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "App", results[0].ProjectDescriptor.Identity.RootComponentName,
		"obj/ is a build artifact directory, so the project is named one level up")
}

func TestPlugin_TargetFile_PackagesConfigNamedAfterItsDirectory(t *testing.T) {
	dir := writeFiles(t, "src/Legacy/packages.config")

	target := filepath.Join("src", "Legacy", "packages.config")
	opts := ecosystems.NewPluginOptions().WithTargetFile(target)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Legacy", results[0].ProjectDescriptor.Identity.RootComponentName)
}

// packages.config directly in the scanned root has no relative directory to be
// named after, so the name comes from the root directory itself.
func TestPlugin_TargetFile_PackagesConfigInScannedRoot(t *testing.T) {
	dir := writeFiles(t, "packages.config")

	opts := ecosystems.NewPluginOptions().WithTargetFile("packages.config")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, filepath.Base(dir), results[0].ProjectDescriptor.Identity.RootComponentName)
}

func TestPlugin_TargetFile_UnsupportedIsSkipped(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj", "package.json")

	opts := ecosystems.NewPluginOptions().WithTargetFile("package.json")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err, "another ecosystem's target file is not this plugin's concern")
	assert.Empty(t, results)
}

func TestPlugin_TargetFile_MissingReturnsError(t *testing.T) {
	dir := writeFiles(t, "MyApp.csproj")

	opts := ecosystems.NewPluginOptions().WithTargetFile("Absent.csproj")

	_, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.Error(t, err, "an explicitly requested target file that does not exist is a setup failure")
}

// A non-nil onGraph error aborts the run and reaches the caller unchanged.
func TestPlugin_OnGraphErrorAbortsRun(t *testing.T) {
	dir := writeFiles(t, "A.csproj", "B.csproj")

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
		"MyApp.csproj":            true,
		"MyApp.vbproj":            true,
		"MyApp.fsproj":            true,
		"MySolution.sln":          true,
		"packages.config":         true,
		"project.assets.json":     true,
		"src/App/App.csproj":      true,
		"obj/project.assets.json": true,
		"package.json":            false,
		"MyApp.csproj.user":       false,
		"project.json":            false,
		"Directory.Build.props":   false,
		"csproj":                  false,
		"":                        false,
	}

	for path, want := range tests {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, want, isSupportedTargetFile(path))
		})
	}
}
