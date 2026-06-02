package cargo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// fakeExecutor returns canned cargo tree / metadata output (or a sentinel
// error) so plugin-level tests can exercise the discover → metadata → tree
// → parse → build pipeline without a real cargo binary.
//
// treeByPkg keys on the package name passed to RunTree; the empty key serves
// the unscoped case. metadataOutput is returned verbatim from RunMetadata.
type fakeExecutor struct {
	metadataOutput string
	metadataErr    error
	treeByPkg      map[string]string
	treeErrByPkg   map[string]error
}

func (f *fakeExecutor) RunMetadata(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.metadataErr != nil {
		return nil, f.metadataErr
	}
	return io.NopCloser(strings.NewReader(f.metadataOutput)), nil
}

func (f *fakeExecutor) RunTree(_ context.Context, _ string, pkg string) (io.ReadCloser, error) {
	if err, ok := f.treeErrByPkg[pkg]; ok {
		return nil, err
	}
	out, ok := f.treeByPkg[pkg]
	if !ok {
		return nil, fmt.Errorf("fakeExecutor: no canned tree output for pkg %q", pkg)
	}
	return io.NopCloser(strings.NewReader(out)), nil
}

// singleCrateMetadata returns cargo metadata JSON for a non-workspace project
// named "my-app" at version "0.1.0" rooted at lockFileAbsDir. Used by every
// happy-path test; tests that need a different package shape build their
// metadata inline.
func singleCrateMetadata(lockFileAbsDir string) string {
	const (
		name    = "my-app"
		version = "0.1.0"
	)
	manifest := filepath.Join(lockFileAbsDir, cargoTomlFile)
	id := fmt.Sprintf("path+file://%s#%s@%s", lockFileAbsDir, name, version)
	return fmt.Sprintf(`{
		"packages": [{
			"name": %q, "version": %q, "id": %q, "manifest_path": %q
		}],
		"workspace_members": [%q],
		"workspace_root": %q
	}`, name, version, id, manifest, id, lockFileAbsDir)
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "cargo", Plugin{}.GetName())
}

func TestBuildDepGraphsFromDir_HappyPath_SingleCrate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))

	output := `0my-app v0.1.0
1serde v1.0.193
2serde_derive v1.0.193 (proc-macro)
1tokio v1.35.0
`

	plugin := Plugin{executor: &fakeExecutor{
		metadataOutput: singleCrateMetadata(dir),
		treeByPkg:      map[string]string{"my-app": output},
	}}

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	require.NoError(t, result.Results[0].Error)

	dg := result.Results[0].DepGraph
	require.NotNil(t, dg)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "0.1.0", dg.GetRootPkg().Info.Version)
	assert.Equal(t, "cargo", dg.PkgManager.Name)
	assert.Len(t, dg.Pkgs, 4)

	tf := result.Results[0].ProjectDescriptor.GetTargetFile()
	assert.Equal(t, cargoTomlFile, tf)
	assert.Equal(t, "cargo", result.Results[0].ProjectDescriptor.Identity.ProjectType)
}

func TestBuildDepGraphsFromDir_NoLockfile(t *testing.T) {
	plugin := Plugin{}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, t.TempDir(), &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	assert.Empty(t, result.Results)
	assert.Empty(t, result.ProcessedFiles)
}

func TestBuildDepGraphsFromDir_CargoNotFound(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))

	plugin := Plugin{executor: &fakeExecutor{metadataErr: errCargoNotFound}}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	require.Error(t, result.Results[0].Error)
	assert.Contains(t, result.Results[0].Error.Error(), "cargo is not installed")
	assert.True(t, errors.Is(result.Results[0].Error, errCargoNotFound))
}

func TestBuildDepGraphsFromDir_TargetFileNotCargoLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))

	tf := "some-other-file.txt"
	plugin := Plugin{}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir,
		(&ecosystems.SCAPluginOptions{}).WithTargetFile(tf))
	require.NoError(t, err)
	assert.Empty(t, result.Results, "non-Cargo.lock target file should produce no results")
}

func TestBuildDepGraphsFromDir_Workspace_TwoMembers(t *testing.T) {
	// Workspace with members a and b, where a depends on b.
	// Expect two SCAResults — one per member — and a's graph should
	// stop-at-leaf at b (not expand b's tokio subtree).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "crates", "a"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "crates", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))

	aManifest := filepath.Join(dir, "crates", "a", cargoTomlFile)
	bManifest := filepath.Join(dir, "crates", "b", cargoTomlFile)

	metadataOut := fmt.Sprintf(`{
		"packages": [
			{"name": "a", "version": "0.1.0", "id": "id-a", "manifest_path": %q},
			{"name": "b", "version": "0.1.0", "id": "id-b", "manifest_path": %q}
		],
		"workspace_members": ["id-a", "id-b"],
		"workspace_root": %q
	}`, aManifest, bManifest, dir)

	// Tree for a: a → b → tokio, plus a → serde.
	treeForA := `0a v0.1.0
1b v0.1.0
2tokio v1.35.0
1serde v1.0.193
`
	// Tree for b: b → tokio.
	treeForB := `0b v0.1.0
1tokio v1.35.0
`

	plugin := Plugin{executor: &fakeExecutor{
		metadataOutput: metadataOut,
		treeByPkg:      map[string]string{"a": treeForA, "b": treeForB},
	}}

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, result.Results, 2)

	byRoot := make(map[string]*ecosystems.SCAResult, 2)
	for i := range result.Results {
		require.NoError(t, result.Results[i].Error)
		byRoot[result.Results[i].DepGraph.GetRootPkg().Info.Name] = &result.Results[i]
	}

	// a's graph: contains a, b, serde — but NOT tokio (it's b's transitive
	// dep, and b is stop-at-leaf in a's graph).
	aDg := byRoot["a"].DepGraph
	aPkgIDs := pkgIDs(aDg.Pkgs)
	assert.ElementsMatch(t, []string{"a@0.1.0", "b@0.1.0", "serde@1.0.193"}, aPkgIDs,
		"a's graph must not expand b's subtree")

	// b's graph: contains b, tokio.
	bDg := byRoot["b"].DepGraph
	bPkgIDs := pkgIDs(bDg.Pkgs)
	assert.ElementsMatch(t, []string{"b@0.1.0", "tokio@1.35.0"}, bPkgIDs)

	// TargetFile paths use the member's manifest path relative to dir.
	assert.Equal(t, filepath.Join("crates", "a", cargoTomlFile), byRoot["a"].ProjectDescriptor.GetTargetFile())
	assert.Equal(t, filepath.Join("crates", "b", cargoTomlFile), byRoot["b"].ProjectDescriptor.GetTargetFile())
}

func TestBuildDepGraphsFromDir_Workspace_OneMemberFailsOthersStillSucceed(t *testing.T) {
	// If cargo tree fails for one member, the other member's graph still
	// emits successfully — failures are captured per-member, not whole-scan.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "b"), 0o755))

	metadataOut := fmt.Sprintf(`{
		"packages": [
			{"name": "a", "version": "0.1.0", "id": "id-a", "manifest_path": %q},
			{"name": "b", "version": "0.1.0", "id": "id-b", "manifest_path": %q}
		],
		"workspace_members": ["id-a", "id-b"],
		"workspace_root": %q
	}`, filepath.Join(dir, "a", cargoTomlFile), filepath.Join(dir, "b", cargoTomlFile), dir)

	plugin := Plugin{executor: &fakeExecutor{
		metadataOutput: metadataOut,
		treeByPkg:      map[string]string{"b": "0b v0.1.0\n"},
		treeErrByPkg:   map[string]error{"a": fmt.Errorf("simulated cargo tree failure")},
	}}

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, result.Results, 2)

	var failedCount, succeededCount int
	for _, r := range result.Results {
		if r.Error != nil {
			failedCount++
			assert.Contains(t, r.Error.Error(), "simulated cargo tree failure")
		} else {
			succeededCount++
			assert.NotNil(t, r.DepGraph)
		}
	}
	assert.Equal(t, 1, failedCount)
	assert.Equal(t, 1, succeededCount)
}

func pkgIDs(pkgs []godepgraph.Pkg) []string {
	ids := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		ids = append(ids, p.ID)
	}
	return ids
}
