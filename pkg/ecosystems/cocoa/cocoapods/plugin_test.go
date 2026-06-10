package cocoapods

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// writeFile is a tiny helper for fixture setup; fails the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// writeSimpleLockfile drops a minimal Podfile.lock into dir so the
// plugin has something to discover.
func writeSimpleLockfile(t *testing.T, dir string) {
	writeFile(t, filepath.Join(dir, "Podfile.lock"), simpleLockfile)
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "cocoapods", Plugin{}.GetName())
}

func TestPlugin_NoLockfile_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_RootLockfile_ProducesOneResult(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)
	assert.Equal(t, "Podfile.lock", r.ProjectDescriptor.GetTargetFile(),
		"with no Podfile manifest present, TargetFile falls back to the lockfile")
	assert.Equal(t, "cocoapods", r.ResolverMetadata.PluginName)
	assert.Equal(t, []string{"Podfile.lock"}, r.ProcessedFiles)
	assert.Equal(t, filepath.Base(dir), r.ProjectDescriptor.Identity.RootComponentName)
}

func TestPlugin_ManifestPriority_PrefersYamlOverPodfile(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)
	// All four manifest variants present — the .yaml one must win.
	writeFile(t, filepath.Join(dir, "Podfile"), "# podfile")
	writeFile(t, filepath.Join(dir, "Podfile.rb"), "# podfile.rb")
	writeFile(t, filepath.Join(dir, "CocoaPods.podfile"), "# cocoapods.podfile")
	writeFile(t, filepath.Join(dir, "CocoaPods.podfile.yaml"), "# yaml")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "CocoaPods.podfile.yaml", results[0].ProjectDescriptor.GetTargetFile())
	assert.Contains(t, results[0].ProcessedFiles, "Podfile.lock")
	assert.Contains(t, results[0].ProcessedFiles, "CocoaPods.podfile.yaml")
}

func TestPlugin_ManifestPriority_FallsThroughToPodfile(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)
	writeFile(t, filepath.Join(dir, "Podfile"), "# podfile")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Podfile", results[0].ProjectDescriptor.GetTargetFile())
}

func TestPlugin_ManifestPriority_PodfileRbAsLastResort(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)
	writeFile(t, filepath.Join(dir, "Podfile.rb"), "# rb")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Podfile.rb", results[0].ProjectDescriptor.GetTargetFile())
}

func TestPlugin_TargetFile_ExplicitLockfile(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)

	opts := ecosystems.NewPluginOptions().WithTargetFile("Podfile.lock")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
}

func TestPlugin_TargetFile_ManifestResolvesToCompanion(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)
	writeFile(t, filepath.Join(dir, "Podfile"), "# podfile")

	opts := ecosystems.NewPluginOptions().WithTargetFile("Podfile")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1, "manifest target file must resolve to the sibling Podfile.lock")
}

func TestPlugin_TargetFile_UnrelatedFile_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)

	opts := ecosystems.NewPluginOptions().WithTargetFile("package.json")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Empty(t, results, "non-cocoapods target file must yield no results")
}

func TestPlugin_AllProjects_FindsNestedLockfiles(t *testing.T) {
	root := t.TempDir()
	writeSimpleLockfile(t, root)
	writeSimpleLockfile(t, filepath.Join(root, "ios"))
	writeSimpleLockfile(t, filepath.Join(root, "macos"))

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), root, opts)
	require.NoError(t, err)
	require.Len(t, results, 3)

	targets := make([]string, 0, len(results))
	for _, r := range results {
		targets = append(targets, r.ProjectDescriptor.GetTargetFile())
	}
	assert.ElementsMatch(t,
		[]string{"Podfile.lock", "ios/Podfile.lock", "macos/Podfile.lock"},
		targets,
	)
}

// TestPlugin_AllProjects_SkipsPodsDir guards against the dep-graph
// picking up vendored Manifest.lock files inside a Pods/ install
// directory — that would duplicate every pod with itself as a sibling
// project.
func TestPlugin_AllProjects_SkipsPodsDir(t *testing.T) {
	root := t.TempDir()
	writeSimpleLockfile(t, root)
	// Pods/Manifest.lock + Pods/SomeVendoredPod/Podfile.lock
	writeFile(t, filepath.Join(root, "Pods", "Podfile.lock"), simpleLockfile)
	writeFile(t, filepath.Join(root, "Pods", "VendoredPod", "Podfile.lock"), simpleLockfile)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), root, opts)
	require.NoError(t, err)

	for _, r := range results {
		tf := r.ProjectDescriptor.GetTargetFile()
		assert.NotContains(t, tf, "Pods/",
			"discovery must skip the Pods/ install directory; got %q", tf)
	}
}

func TestPlugin_AllProjects_HonorsExcludePaths(t *testing.T) {
	root := t.TempDir()
	writeSimpleLockfile(t, root)
	writeSimpleLockfile(t, filepath.Join(root, "ios"))
	writeSimpleLockfile(t, filepath.Join(root, "skipme"))

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"skipme"})

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), root, opts)
	require.NoError(t, err)

	for _, r := range results {
		assert.NotContains(t, r.ProjectDescriptor.GetTargetFile(), "skipme")
	}
}

func TestPlugin_MalformedLockfile_ReturnsErrorResult(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Podfile.lock"), "this : is : not : valid : podfile.lock\n:::]")

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err, "parse failure must surface as a per-result error, not abort the run")
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.Nil(t, results[0].DepGraph)
	assert.NotNil(t, results[0].ProjectDescriptor.Identity.TargetFile, "error results still carry a target file")
}

func TestPlugin_NilOptions_UsesDefaults(t *testing.T) {
	dir := t.TempDir()
	writeSimpleLockfile(t, dir)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
}

// TestPlugin_StopsOnGraphError verifies the SCAPlugin contract that a
// non-nil onGraph return aborts the run and the same error reaches the
// caller.
func TestPlugin_StopsOnGraphError(t *testing.T) {
	root := t.TempDir()
	writeSimpleLockfile(t, root)
	writeSimpleLockfile(t, filepath.Join(root, "ios"))

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	sentinel := assertSentinel{}
	err := Plugin{}.BuildDepGraphsFromDir(context.Background(), logger.Nop(), root, opts,
		func(_ ecosystems.SCAResult) error { return &sentinel },
	)
	require.ErrorIs(t, err, &sentinel)
}

type assertSentinel struct{}

func (a *assertSentinel) Error() string { return "sentinel" }
