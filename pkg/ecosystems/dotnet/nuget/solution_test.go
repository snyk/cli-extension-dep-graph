package nuget

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

const slnxFile = "MySolution.slnx"

// twoProjectSlnx holds one project at the top level and one inside a solution
// folder, with the separators each side of the format tends to be written with.
const twoProjectSlnx = `<Solution>
  <Project Path="Service\Service.csproj" />
  <Folder Name="/tests/">
    <Project Path="Service.Tests/Service.Tests.csproj" />
  </Folder>
</Solution>`

// slnxWith writes a .slnx of the given content into a fresh temp dir alongside
// an assets file for each named project directory.
func slnxWith(t *testing.T, content string, restoredProjectDirs ...string) string {
	t.Helper()

	dir := t.TempDir()
	write(t, dir, slnxFile, content)

	for _, projectDir := range restoredProjectDirs {
		write(t, dir, filepath.Join(projectDir, objDir, projectAssetsFile), singleTargetAssets)
	}

	return dir
}

func runWithTargetFile(t *testing.T, dir, targetFile string, log logger.Logger) []ecosystems.SCAResult {
	t.Helper()

	results, err := scatest.Run(context.Background(), Plugin{}, log, dir,
		ecosystems.NewPluginOptions().WithTargetFile(targetFile))
	require.NoError(t, err)

	return results
}

// --file=App.slnx selects the projects the solution holds, the same way
// --file=App.sln always has in the legacy CLI.
func TestPlugin_SlnxTargetFile_ResolvesEveryProject(t *testing.T) {
	dir := slnxWith(t, twoProjectSlnx, "Service", "Service.Tests")

	results := runWithTargetFile(t, dir, slnxFile, logger.Nop())

	require.Len(t, results, 2)
	assert.ElementsMatch(t, []string{
		filepath.Join("Service", objDir, projectAssetsFile),
		filepath.Join("Service.Tests", objDir, projectAssetsFile),
	}, relPaths(t, results))

	for _, result := range results {
		require.NoError(t, result.Error)
		require.NotNil(t, result.DepGraph)
	}

	// Each project is named after its own directory, not the solution's.
	names := make([]string, len(results))
	for i, result := range results {
		names[i] = result.ProjectDescriptor.Identity.RootComponentName
	}
	assert.ElementsMatch(t, []string{"Service", "Service.Tests"}, names)
}

// The projects a solution holds are claimed, so the legacy resolver does not
// report them a second time.
func TestPlugin_SlnxTargetFile_ClaimsTheProjectsItResolved(t *testing.T) {
	dir := slnxWith(t, twoProjectSlnx, "Service", "Service.Tests")

	results := runWithTargetFile(t, dir, slnxFile, logger.Nop())

	require.Len(t, results, 2)
	for _, result := range results {
		assert.Equal(t, []string{result.ResolverMetadata.NormalisedTargetFile}, result.ProcessedFiles)
	}
}

// All or nothing: one unrestored project and the whole solution goes to the
// legacy resolver, which can reach projects this resolver cannot. Claiming the
// restored subset would silently drop the rest.
func TestPlugin_SlnxTargetFile_UnrestoredProjectLeavesSolutionToLegacy(t *testing.T) {
	dir := slnxWith(t, twoProjectSlnx, "Service")

	log := &recordingLogger{}
	results := runWithTargetFile(t, dir, slnxFile, log)

	assert.Empty(t, results, "a partially restored solution is left to the legacy resolver")
	assert.Contains(t, log.debug, msgSolutionUnrestored)
}

// An assets file that exists but cannot be used is the case a target-file
// existence check cannot see. The project it belongs to would report nothing
// while its siblings reported results — and because the workflow stops after the
// first resolver that reports anything, nobody else would ever look at it.
func TestPlugin_SlnxTargetFile_UnusableAssetsLeavesSolutionToLegacy(t *testing.T) {
	for name, assets := range map[string]string{
		"not json":            `{ not json`,
		"empty object":        `{}`,
		"no frameworks":       `{"version":3,"targets":{"net8.0":{}},"project":{"version":"1.0.0"}}`,
		"frameworks is empty": `{"version":3,"targets":{},"project":{"version":"1.0.0","frameworks":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := slnxWith(t, twoProjectSlnx, "Service")
			write(t, dir, filepath.Join("Service.Tests", objDir, projectAssetsFile), assets)

			log := &recordingLogger{}
			results := runWithTargetFile(t, dir, slnxFile, log)

			assert.Empty(t, results,
				"the solution is left to the legacy resolver rather than reported in part")
			assert.Contains(t, log.debug, msgSolutionUnresolvable)
		})
	}
}

// Every other resolver walks down from the scanned directory, so a target file's
// path relative to it is always inside it — and that path is the project's
// identity. A solution can reference anywhere on disk, so rather than mint a
// `../`-shaped identity, the solution goes to the legacy resolver.
func TestPlugin_SlnxTargetFile_ProjectOutsideScanLeavesSolutionToLegacy(t *testing.T) {
	root := t.TempDir()
	scanned := filepath.Join(root, "scanned")
	write(t, scanned, slnxFile, `<Solution>
  <Project Path="../Outside/Outside.csproj" />
</Solution>`)
	write(t, root, filepath.Join("Outside", objDir, projectAssetsFile), singleTargetAssets)

	log := &recordingLogger{}
	results := runWithTargetFile(t, scanned, slnxFile, log)

	assert.Empty(t, results)
	assert.Contains(t, log.debug, msgSolutionEscapesScan)
}

// A hand-edited or badly merged solution can name one project several ways, or
// name two projects that share a directory. All of those resolve to a single
// assets file, and reporting it once per mention would submit the same project
// repeatedly.
func TestPlugin_SlnxTargetFile_DeduplicatesProjectsSharingAnAssetsFile(t *testing.T) {
	t.Run("the same project named three ways", func(t *testing.T) {
		dir := slnxWith(t, `<Solution>
  <Project Path="Service/Service.csproj" />
  <Project Path="Service\Service.csproj" />
  <Project Path="Service/" />
</Solution>`, "Service")

		results := runWithTargetFile(t, dir, slnxFile, logger.Nop())

		require.Len(t, results, 1)
		assert.Equal(t, filepath.Join("Service", objDir, projectAssetsFile), relPaths(t, results)[0])
	})

	t.Run("two projects in one directory", func(t *testing.T) {
		dir := slnxWith(t, `<Solution>
  <Project Path="Service/Service.csproj" />
  <Project Path="Service/Service.Alt.csproj" />
</Solution>`, "Service")

		results := runWithTargetFile(t, dir, slnxFile, logger.Nop())

		require.Len(t, results, 1,
			"one assets file describes one project, however many name it")
	})
}

// A path relative to the solution rather than to the scanned directory, and one
// pointing outside it, both have to resolve against the solution's own folder.
func TestPlugin_SlnxTargetFile_ResolvesPathsAgainstTheSolutionFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, filepath.Join("solution", slnxFile), `<Solution>
  <Project Path="../Service/Service.csproj" />
  <Project Path="Nested/Nested.csproj" />
</Solution>`)
	write(t, dir, filepath.Join("Service", objDir, projectAssetsFile), singleTargetAssets)
	write(t, dir, filepath.Join("solution", "Nested", objDir, projectAssetsFile), singleTargetAssets)

	results := runWithTargetFile(t, dir, filepath.Join("solution", slnxFile), logger.Nop())

	require.Len(t, results, 2)
	assert.ElementsMatch(t, []string{
		filepath.Join("Service", objDir, projectAssetsFile),
		filepath.Join("solution", "Nested", objDir, projectAssetsFile),
	}, relPaths(t, results))
}

// A project path that already names the project's directory.
func TestPlugin_SlnxTargetFile_AcceptsADirectoryPath(t *testing.T) {
	dir := slnxWith(t, `<Solution>
  <Project Path="Service/" />
</Solution>`, "Service")

	results := runWithTargetFile(t, dir, slnxFile, logger.Nop())

	require.Len(t, results, 1)
	assert.Equal(t, filepath.Join("Service", objDir, projectAssetsFile), relPaths(t, results)[0])
}

// An empty or unreadable solution is not an error: reporting nothing is how a
// resolver says "not my project", and the legacy resolver still gets a look.
func TestPlugin_SlnxTargetFile_EmptyAndBrokenSolutionsClaimNothing(t *testing.T) {
	t.Run("no projects", func(t *testing.T) {
		dir := slnxWith(t, `<Solution />`)

		log := &recordingLogger{}
		assert.Empty(t, runWithTargetFile(t, dir, slnxFile, log))
		assert.Contains(t, log.debug, msgSolutionHoldsNothing)
	})

	t.Run("not valid XML", func(t *testing.T) {
		dir := slnxWith(t, `<Solution><Project Path="Service/Service.csproj"`)

		log := &recordingLogger{}
		assert.Empty(t, runWithTargetFile(t, dir, slnxFile, log))
		assert.Contains(t, log.errs, msgSolutionUnreadable)
	})

	t.Run("solution file does not exist", func(t *testing.T) {
		log := &recordingLogger{}
		assert.Empty(t, runWithTargetFile(t, t.TempDir(), slnxFile, log))
		assert.Contains(t, log.errs, msgSolutionUnreadable)
	})
}

// The text format keeps going to the legacy resolver: its project entries also
// carry solution folders and project types this resolver has nothing to say
// about, so claiming them here would change behavior rather than add it.
func TestPlugin_SlnTargetFileIsLeftToLegacy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "MySolution.sln", "")
	write(t, dir, filepath.Join("Service", objDir, projectAssetsFile), singleTargetAssets)

	assert.Empty(t, runWithTargetFile(t, dir, "MySolution.sln", logger.Nop()))
}

func TestIsSlnxFile(t *testing.T) {
	for file, expected := range map[string]bool{
		"MySolution.slnx":         true,
		"MySolution.SLNX":         true,
		"path/to/MySolution.slnx": true,
		"MySolution.sln":          false,
		"MySolution.slnf":         false,
		"MyApp.csproj":            false,
		"slnx":                    false,
		projectAssetsFile:         false,
	} {
		assert.Equal(t, expected, isSlnxFile(file), file)
	}
}

func TestSolutionProjectDir(t *testing.T) {
	solutionDir := filepath.Join("repo", "solution")

	assert.Equal(t,
		filepath.Join(solutionDir, "Service"),
		solutionProjectDir(solutionDir, `Service\Service.csproj`),
		"windows separators resolve on every platform")

	assert.Equal(t,
		filepath.Join(solutionDir, "Service"),
		solutionProjectDir(solutionDir, "Service/Service.csproj"))

	assert.Equal(t,
		filepath.Join(solutionDir, "Service"),
		solutionProjectDir(solutionDir, "Service/"),
		"a trailing separator names the project directory itself")

	assert.Equal(t,
		filepath.Join("repo", "Service"),
		solutionProjectDir(solutionDir, "../Service/Service.csproj"),
		"a project can sit outside the solution's own folder")

	assert.Equal(t,
		filepath.Join(solutionDir, "My.App.Core"),
		solutionProjectDir(solutionDir, "My.App.Core/My.App.Core.csproj"),
		"dots in a directory name are not an extension")
}

func TestParseSlnx_CollectsProjectsAtEveryDepth(t *testing.T) {
	dir := t.TempDir()
	// Nesting is expressed by slash-delimited Folder names, not by nesting the
	// elements: the .slnx schema (microsoft/vs-solutionpersistence Slnx.xsd)
	// allows File, Project and Properties inside a Folder, but not another
	// Folder. This is the shape Visual Studio and `dotnet sln migrate` write.
	path := write(t, dir, slnxFile, `<?xml version="1.0" encoding="utf-8"?>
<Solution>
  <Project Path="A/A.csproj">
    <BuildType Solution="Debug|Any CPU" Project="Debug" />
  </Project>
  <Folder Name="/src/">
    <Project Path="B/B.csproj" />
  </Folder>
  <Folder Name="/src/deep/">
    <Project Path="C/C.csproj" />
  </Folder>
  <Folder Name="/items/">
    <File Path="README.md" />
  </Folder>
  <Folder Name="/empty/" />
  <Project />
</Solution>`)

	paths, err := parseSlnx(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"A/A.csproj", "B/B.csproj", "C/C.csproj"}, paths,
		"every Project element and nothing else")
}

// A project recorded as a URI is legal and appears in Microsoft's own sample
// assets. It can never resolve to an assets file on disk, so the solution goes
// to the legacy resolver rather than being claimed in part.
func TestPlugin_SlnxTargetFile_UriProjectLeavesSolutionToLegacy(t *testing.T) {
	dir := slnxWith(t, `<Solution>
  <Project Path="Service/Service.csproj" />
  <Project Path="http://localhost:8080" />
</Solution>`, "Service")

	log := &recordingLogger{}

	assert.Empty(t, runWithTargetFile(t, dir, slnxFile, log))
	assert.Contains(t, log.debug, msgSolutionUnrestored)
}

// An ASP.NET Website project is recorded as a folder, with no project file and
// so no assets file. Same outcome, reached by the trailing-separator path.
func TestPlugin_SlnxTargetFile_WebsiteProjectLeavesSolutionToLegacy(t *testing.T) {
	dir := slnxWith(t, `<Solution>
  <Project Path="Service/Service.csproj" />
  <Project Path="WebSite1/" Type="Website" DisplayName="WebSite1" />
</Solution>`, "Service")
	write(t, dir, filepath.Join("WebSite1", "packages.config"), "")

	log := &recordingLogger{}

	assert.Empty(t, runWithTargetFile(t, dir, slnxFile, log))
	assert.Contains(t, log.debug, msgSolutionUnrestored)
}
