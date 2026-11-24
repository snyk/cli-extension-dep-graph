package uv

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/metadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

func TestUVClient_Version(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		execErr error
		want    string
		wantErr bool
	}{
		{name: "release build", output: "uv 0.12.5 (a1b2c3d 2026-09-02)\n", want: "0.12.5"},
		{name: "bare version", output: "uv 0.9.29\n", want: "0.9.29"},
		{name: "unparseable output", output: "uv dev\n", wantErr: true},
		{name: "a prerelease reads as its base version", output: "uv 0.12.5-alpha.1 (a1b2c3d 2026-09-01)\n", want: "0.12.5"},
		{
			name:   "a shim's warning line before uv's own is ignored",
			output: "mise WARN 2026.1.3 a newer version is available\nuv 0.12.4 (a1b2c3d 2026-08-20)\n",
			want:   "0.12.4",
		},
		{name: "a version on any other line is not uv's", output: "mise WARN 2026.1.3 uv is not installed\n", wantErr: true},
		{name: "uv must start the line", output: "not uv 0.12.5\n", wantErr: true},
		{name: "command fails", execErr: errors.New("boom"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &mockCmdExecutor{versionFunc: func(binary string) ([]byte, error) {
				assert.Equal(t, "/path/to/uv", binary)
				return []byte(tt.output), tt.execErr
			}}

			got, err := NewClientWithExecutor("/path/to/uv", exec).Version()

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPlugin_ReportsUvVersion(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml")
	client := &MockClient{UvVersion: "0.12.5"}

	results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(), ""), testLogger, tmpDir, ecosystems.NewPluginOptions())

	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NotNil(t, results[0].ResolverMetadata)
	assert.Equal(t, map[string]string{metadata.UvVersion: "0.12.5"}, results[0].ResolverMetadata.VersionBuildInfo)
}

func TestPlugin_AsksForUvVersionOncePerScan(t *testing.T) {
	tmpDir := createFiles(t, "a/uv.lock", "a/pyproject.toml", "b/uv.lock", "b/pyproject.toml")
	client := &MockClient{UvVersion: "0.12.5"}

	results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(), ""), testLogger, tmpDir,
		ecosystems.NewPluginOptions().WithAllProjects(true))

	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, 1, client.VersionCalls)
	for _, r := range results {
		assert.Equal(t, "0.12.5", r.ResolverMetadata.VersionBuildInfo[metadata.UvVersion])
	}
}

// A version we cannot read must not fail the scan: it is diagnostic data.
func TestPlugin_OmitsUvVersionWhenUnavailable(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml")
	client := &MockClient{VersionErr: errors.New("boom")}

	results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(), ""), testLogger, tmpDir, ecosystems.NewPluginOptions())

	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Empty(t, results[0].ResolverMetadata.VersionBuildInfo)
}

// No lockfile, no uv: the version is read only when there is a project to scan.
func TestPlugin_DoesNotAskForUvVersionWithoutLockfile(t *testing.T) {
	tmpDir := createFiles(t, "pyproject.toml")
	client := &MockClient{UvVersion: "0.12.5"}

	results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(), ""), testLogger, tmpDir, ecosystems.NewPluginOptions())

	require.NoError(t, err)
	assert.Empty(t, results)
	assert.Zero(t, client.VersionCalls)
}

// Execute checks the version before every command, so a Version built on it
// would start uv twice. Version must start it exactly once: a fake uv counts
// its own invocations.
func TestUVClient_Version_StartsUvOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake uv is a shell script")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	fakeUv := filepath.Join(dir, "uv")
	script := "#!/bin/sh\necho \"$@\" >> '" + calls + "'\necho 'uv 0.12.22 (70fe1196a 2026-10-01)'\n"
	require.NoError(t, os.WriteFile(fakeUv, []byte(script), 0o700)) //nolint:gosec // an executable test double

	got, err := NewClientWithPath(fakeUv).Version()

	require.NoError(t, err)
	assert.Equal(t, "0.12.22", got)
	logged, err := os.ReadFile(calls)
	require.NoError(t, err)
	assert.Equal(t, []string{"--version"}, strings.Fields(string(logged)), "uv is started once, for --version only")
}

func TestUVClient_Version_MissingBinary(t *testing.T) {
	_, err := NewClientWithPath(filepath.Join(t.TempDir(), "no-such-uv")).Version()

	require.Error(t, err)
}

// A failed export still reports the uv version, which is the diagnostic for
// scans that fail on an old uv.
func TestPlugin_ExportFailureCarriesUvVersion(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml")
	client := &MockClient{UvVersion: "0.9.29", ReturnErr: errors.New("export failed")}

	results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(), ""), testLogger, tmpDir, ecosystems.NewPluginOptions())

	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	assert.Equal(t, map[string]string{metadata.UvVersion: "0.9.29"}, results[0].ResolverMetadata.VersionBuildInfo)
}

// Every error result of a scan carries the uv version, not only successes.
func TestPlugin_ErrorResultsCarryUvVersion(t *testing.T) {
	tests := map[string]struct {
		sbom    []byte
		options *ecosystems.SCAPluginOptions
	}{
		"workspace with no root project": {virtualWorkspaceSBOMJSON, ecosystems.NewPluginOptions()},
		"workspace package not found":    {workspaceSBOMJSON, ecosystems.NewPluginOptions().WithWorkspacePackage("no-such-member")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tmpDir := createFiles(t, "uv.lock", "pyproject.toml")
			client := &MockClient{UvVersion: "0.12.5", SBOM: Sbom(tt.sbom)}

			results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(createTestDepGraph("member", "1.0.0")), ""), testLogger, tmpDir, tt.options)

			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Error(t, results[0].Error)
			assert.Equal(t, map[string]string{metadata.UvVersion: "0.12.5"}, results[0].ResolverMetadata.VersionBuildInfo)
		})
	}
}

func TestPlugin_ObservesUvVersionOncePerScan(t *testing.T) {
	tmpDir := createFiles(t, "a/uv.lock", "a/pyproject.toml", "b/uv.lock", "b/pyproject.toml")
	var observed []string
	plugin := NewPlugin(&MockClient{UvVersion: "0.12.5"}, mockConverter(), "",
		WithVersionObserver(func(v string) { observed = append(observed, v) }))

	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, ecosystems.NewPluginOptions().WithAllProjects(true))

	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, []string{"0.12.5"}, observed, "two lockfiles, one scan, one observation")
}

func TestPlugin_DoesNotObserveAnUnknownUvVersion(t *testing.T) {
	for name, client := range map[string]*MockClient{
		"version error": {VersionErr: errors.New("boom")},
		"empty version": {},
	} {
		t.Run(name, func(t *testing.T) {
			tmpDir := createFiles(t, "uv.lock", "pyproject.toml")
			observed := false
			plugin := NewPlugin(client, mockConverter(), "", WithVersionObserver(func(string) { observed = true }))

			_, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, ecosystems.NewPluginOptions())

			require.NoError(t, err)
			assert.False(t, observed)
		})
	}
}
