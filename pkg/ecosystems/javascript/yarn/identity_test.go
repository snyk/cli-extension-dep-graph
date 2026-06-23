package yarn

// identity_test.go pins down the identity contract this plugin must honor
// to keep migrated yarn projects pointing at the same backend identity they
// had under snyk-nodejs-lockfile-parser. The contract is documented on
// buildResults in plugin.go; this file asserts it stays true.
//
// The legacy yarn path (snyk-nodejs-plugin → cli/run-test.ts) does NOT set
// plugin.targetFile, which translates to nil Identity.TargetFile in
// cli-extension-dep-graph's legacy plugin. Downstream
// (pkg/depgraph/sbom_resolution.go) uses Identity.TargetFile's nilness to
// gate emission of MetaKeyTargetFileFromPlugin onto workflow data — and the
// backend treats that key as part of project uniqueness (the CLI's own
// PayloadBody.targetFile carries the matching warning comment). So if this
// plugin starts emitting a non-nil TargetFile, every existing yarn project
// looks "new" on the next scan.
//
// Lives in the yarn package (not yarn_test) so the fake executor can satisfy
// the unexported yarnRunner interface — same pattern bun's plugin_test.go
// uses to drive Plugin without needing a real yarn binary in PATH.

import (
	"bytes"
	"context"
	"io"
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

// identityFakeExecutor satisfies yarnRunner with a canned `yarn list` payload
// for the Classic v1 path. Keeps the test self-contained and deterministic.
type identityFakeExecutor struct {
	output  string
	version string
}

func (f *identityFakeExecutor) Run(_ context.Context, _ string) (*yarnRunResult, error) {
	return &yarnRunResult{
		Output:  io.NopCloser(bytes.NewReader([]byte(f.output))),
		Family:  familyClassic,
		Version: f.version,
	}, nil
}

// TestIdentity_NonWorkspace_MatchesLegacy asserts that for a vanilla
// non-workspace yarn project the plugin emits exactly the identity shape
// legacy snyk-nodejs-plugin produced.
func TestIdentity_NonWorkspace_MatchesLegacy(t *testing.T) {
	dir := t.TempDir()
	writeIdentityFixture(t, dir, `{
		"name": "my-app",
		"version": "1.2.3",
		"dependencies": {"accepts": "1.3.7"}
	}`, classicSimpleLockfile)

	// Minimal yarn list output: one resolved package matching the manifest
	// dep, no warnings, no children to keep the test focused on identity.
	listOutput := `{"type":"tree","data":{"type":"list","trees":[{"name":"accepts@1.3.7","children":[],"hint":null,"color":null,"depth":0}]}}`

	plugin := Plugin{executor: &identityFakeExecutor{output: listOutput, version: "1.22.19"}}
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir,
		&ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 1, "non-workspace project yields a single SCAResult")

	r := results[0]
	require.NoError(t, r.Error)

	// Identity contract.
	assert.Equal(t, "yarn", r.ProjectDescriptor.Identity.ProjectType,
		"ProjectType must match dg.PkgManager.Name (legacy parity)")
	assert.Nil(t, r.ProjectDescriptor.Identity.TargetFile,
		"Identity.TargetFile must be nil (legacy snyk-nodejs-plugin doesn't set plugin.targetFile)")
	assert.Equal(t, "my-app", r.ProjectDescriptor.Identity.RootComponentName,
		"RootComponentName comes from package.json `name` (legacy parity)")
	assert.Nil(t, r.ProjectDescriptor.Identity.TargetRuntime,
		"TargetRuntime is not set by legacy snyk-nodejs-plugin")

	// NormalisedTargetFile is the lockfile (matches what CLI auto-discovery
	// would have passed for a non-workspace yarn scan).
	assert.Equal(t, "yarn.lock", r.ResolverMetadata.NormalisedTargetFile,
		"non-workspace NormalisedTargetFile must be the lockfile")

	// ProcessedFiles: lockfile only — TargetFile is nil so no extra entry.
	assert.Equal(t, []string{"yarn.lock"}, r.ProcessedFiles,
		"ProcessedFiles contains only the lockfile when there's no separate manifest path")
}

// TestIdentity_Workspaces_MatchesLegacy asserts that for a workspace project
// the per-workspace SCAResult identity matches legacy: TargetFile nil,
// NormalisedTargetFile = workspace's package.json relative path. The root
// SCAResult uses the lockfile path (new emission, no legacy collision —
// existing workspace identities are preserved through the workspace results).
func TestIdentity_Workspaces_MatchesLegacy(t *testing.T) {
	dir := t.TempDir()
	writeIdentityFixture(t, dir, `{
		"name": "monorepo",
		"version": "1.0.0",
		"workspaces": ["packages/*"]
	}`, classicSimpleLockfile)

	// Workspace member manifest. Its declared dep matches the lockfile.
	writeIdentityFile(t, filepath.Join(dir, "packages/a/package.json"), `{
		"name": "@my/a",
		"version": "0.1.0",
		"dependencies": {"accepts": "1.3.7"}
	}`)

	// yarn list output emits the workspace as its own tree entry (same form
	// as workspace-with-cross-ref shows; we verified this with real yarn 1
	// earlier in the parser commits).
	listOutput := strings.Join([]string{
		`{"type":"tree","data":{"type":"list","trees":[`,
		`{"name":"@my/a@0.1.0","children":[{"name":"accepts@1.3.7","color":"dim","shadow":true}],"hint":null,"color":"bold","depth":0},`,
		`{"name":"accepts@1.3.7","children":[],"hint":null,"color":null,"depth":0}`,
		`]}}`,
	}, "")

	plugin := Plugin{executor: &identityFakeExecutor{output: listOutput, version: "1.22.19"}}
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir,
		&ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 2, "workspace project yields root + per-workspace SCAResults")

	root, ws := results[0], results[1]
	require.NoError(t, root.Error)
	require.NoError(t, ws.Error)

	// Both results: nil TargetFile, ProjectType yarn.
	for _, r := range []ecosystems.SCAResult{root, ws} {
		assert.Nil(t, r.ProjectDescriptor.Identity.TargetFile,
			"every yarn SCAResult must have nil Identity.TargetFile")
		assert.Equal(t, "yarn", r.ProjectDescriptor.Identity.ProjectType)
	}

	// Root SCAResult: NormalisedTargetFile is the lockfile.
	assert.Equal(t, "yarn.lock", root.ResolverMetadata.NormalisedTargetFile,
		"root SCAResult of a workspace project uses the lockfile")
	assert.Equal(t, "monorepo", root.ProjectDescriptor.Identity.RootComponentName)

	// Workspace SCAResult: NormalisedTargetFile is the workspace's pkg.json
	// relative to the scan root — matches legacy
	// snyk-nodejs-plugin/lib/workspaces/yarn-workspaces-parser.ts line 199:
	//   targetFile: pathUtil.relative(root, packageJson.fileName)
	expectedWsPath := filepath.Join("packages", "a", "package.json")
	assert.Equal(t, expectedWsPath, ws.ResolverMetadata.NormalisedTargetFile,
		"workspace SCAResult uses its own package.json relative path (legacy parity)")
	assert.Equal(t, "@my/a", ws.ProjectDescriptor.Identity.RootComponentName)

	// ProcessedFiles for the workspace result includes both the lockfile and
	// the workspace pkg.json (since they differ).
	assert.Contains(t, ws.ProcessedFiles, "yarn.lock")
	assert.Contains(t, ws.ProcessedFiles, expectedWsPath)
}

// TestIdentity_ErrorResult_MatchesContract verifies the error path also
// honors the identity contract — nil TargetFile, lockfile as
// NormalisedTargetFile. Failed scans must not be identified differently
// from successful ones, or backend project history breaks on the first error.
func TestIdentity_ErrorResult_MatchesContract(t *testing.T) {
	dir := t.TempDir()
	// Manifest is missing a `name` field — buildResults goes down the
	// errResult path with "package.json is missing a \"name\" field" before
	// it ever invokes the executor.
	writeIdentityFixture(t, dir, `{"version": "1.0.0"}`, classicSimpleLockfile)

	plugin := Plugin{executor: &identityFakeExecutor{output: "", version: "1.22.19"}}
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir,
		&ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.Error(t, r.Error, "missing-name should produce an error result")

	assert.Nil(t, r.ProjectDescriptor.Identity.TargetFile,
		"error SCAResult must also use nil Identity.TargetFile")
	assert.Equal(t, "yarn", r.ProjectDescriptor.Identity.ProjectType)
	assert.Equal(t, "yarn.lock", r.ResolverMetadata.NormalisedTargetFile,
		"error SCAResult's NormalisedTargetFile is the lockfile that triggered the scan")
}

// writeIdentityFixture writes a package.json + yarn.lock pair into dir.
func writeIdentityFixture(t *testing.T, dir, pkgJSON, yarnLock string) {
	t.Helper()
	writeIdentityFile(t, filepath.Join(dir, "package.json"), pkgJSON)
	writeIdentityFile(t, filepath.Join(dir, "yarn.lock"), yarnLock)
}

// writeIdentityFile writes content to path, creating parent dirs as needed.
// Local helper to keep this test file self-contained — the other test files
// have their own copies for the same reason.
func writeIdentityFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// classicSimpleLockfile is a minimal yarn v1 lockfile pinning accepts@1.3.7.
// The plugin doesn't parse the lockfile beyond the spec→resolved pre-pass,
// so this is just enough to satisfy that.
const classicSimpleLockfile = `# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1


accepts@1.3.7:
  version "1.3.7"
  resolved "https://example.com/accepts-1.3.7.tgz"
`
