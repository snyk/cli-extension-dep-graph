//go:build !integration
// +build !integration

package pip

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/metadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// fakePython puts python3 and pip stand-ins first on PATH. Each reports a
// version for --version and, for `install`, prints report (or fails when
// report is empty). They record their working directory and arguments, one
// call per line, so tests can see how and where the plugin invoked them.
func fakePython(t *testing.T, report string) (argsLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script interpreter stand-in")
	}
	dir := t.TempDir()
	argsLog = filepath.Join(dir, "args.log")
	reportFile := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(reportFile, []byte(report), 0o600))
	pipStep := "cat '" + reportFile + "'"
	if report == "" {
		pipStep = "echo 'ERROR: Could not find a version that satisfies the requirement' >&2; exit 1"
	}
	script := "#!/bin/sh\necho \"$PWD $@\" >> '" + argsLog + "'\n" +
		"if [ \"$1\" = --version ]; then echo 'Python 3.12.1'; exit 0; fi\n" + pipStep + "\n"
	for _, name := range []string{"python3", "pip"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0o600))
		require.NoError(t, os.Chmod(filepath.Join(dir, name), 0o700))
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/bin"+string(os.PathListSeparator)+"/usr/bin")
	return argsLog
}

func TestPlugin_ComponentMetadata(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("alpha==1.0\n"), 0o600))
	fakePython(t, reportJSON(`{"url":"https://files.example/alpha-1.0.whl","archive_info":{"hashes":{"sha256":"`+sha256Hex+`"}}}`))

	for _, include := range []bool{true, false} {
		opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(include)
		results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Error)
		assert.Equal(t, "3.12.1", results[0].ResolverMetadata.VersionBuildInfo[metadata.PythonVersion])

		var labels map[string]string
		for _, n := range results[0].DepGraph.Graph.Nodes {
			if n.NodeID == "alpha@1.0" && n.Info != nil {
				labels = n.Info.Labels
			}
		}
		if include {
			assert.Equal(t, map[string]string{"hash:sha-256": sha256Hex, "distribution:url": "https://files.example/alpha-1.0.whl"}, labels)
		} else {
			assert.Nil(t, labels, "flag off: graph unchanged")
		}
	}
}

// With component metadata requested, --file claims only requirements.txt;
// anything else is left for the plugin that owns it (pipenv, or
// snyk-python-plugin for setup.py and non-standard requirements names, which
// need --package-manager there). Without the flag --file is used as given.
func TestPlugin_TargetFileScoping(t *testing.T) {
	fakePython(t, reportJSON(`{"url":"https://h/a.whl"}`))
	for _, tt := range []struct {
		file  string
		claim bool
	}{
		{"requirements.txt", true},
		{"sub/requirements.txt", true},
		{"Pipfile", false},
		{"Pipfile.lock", false},
		{"setup.py", false},
		{"requirements-dev.txt", false},
		{"pyproject.toml", false},
	} {
		t.Run(tt.file, func(t *testing.T) {
			dir := t.TempDir()
			full := filepath.Join(dir, tt.file)
			require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
			require.NoError(t, os.WriteFile(full, []byte("alpha==1.0\n"), 0o600))

			opts := ecosystems.NewPluginOptions().WithTargetFile(tt.file)
			results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
			require.NoError(t, err)
			require.Len(t, results, 1, "flag off: --file is processed whatever its name")
			assert.Equal(t, []string{tt.file}, results[0].ProcessedFiles)

			results, err = scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts.WithIncludeComponentMetadata(true))
			require.NoError(t, err)
			if !tt.claim {
				assert.Empty(t, results)
				return
			}
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)
			assert.Equal(t, []string{tt.file}, results[0].ProcessedFiles)
		})
	}
}

// pip resolves bare and -e paths (`-e .`, `./pkg`) against its working
// directory; -r and -c are relative to the file. With component metadata
// requested, under --file or for a manifest at the root, that directory is
// the scan root, as when the CLI runs from it (`--file=deploy/requirements.txt`
// with `-e .` names the root project), and a sub-manifest found by
// --all-projects resolves from its own directory. Without the flag pip runs
// in the process's working directory, as before.
func TestPlugin_WorkingDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	for _, tt := range []struct {
		name               string
		flag               bool
		opts               func(*ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions
		wantRel            string // relative to the scan root; "" means the process cwd
		wantProbeInRootDir bool
	}{
		{"flag on, --file uses the scan root", true, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithTargetFile("svc/requirements.txt")
		}, ".", true},
		{"flag on, --all-projects sub-manifest uses its directory", true, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithAllProjects(true)
		}, "svc", true},
		{"flag off, --file uses the process cwd", false, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithTargetFile("svc/requirements.txt")
		}, "", false},
		{"flag off, --all-projects uses the process cwd", false, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithAllProjects(true)
		}, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "svc", "requirements.txt"), "-e .\n")
			argsLog := fakePython(t, reportJSON(""))

			_, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir,
				tt.opts(ecosystems.NewPluginOptions().WithIncludeComponentMetadata(tt.flag)))
			require.NoError(t, err)

			wantPip, wantProbe := cwd, cwd
			if tt.wantRel != "" {
				wantPip = filepath.Join(dir, tt.wantRel)
			}
			if tt.wantProbeInRootDir {
				wantProbe = dir
			}
			calls := loggedCalls(t, argsLog)
			require.Len(t, calls, 2)
			assert.Equal(t, wantProbe, strings.SplitN(calls[0], " ", 2)[0], calls[0])
			assert.Contains(t, calls[0], " --version")
			assert.Equal(t, wantPip, strings.SplitN(calls[1], " ", 2)[0], calls[1])
			assert.Contains(t, calls[1], " install --dry-run")
		})
	}
}

// As on main, a missing interpreter fails the plugin, with or without the flag.
func TestPlugin_MissingInterpreterFailsThePlugin(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "alpha==1.0\n")
	t.Setenv("PATH", t.TempDir())
	for _, include := range []bool{false, true} {
		_, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir,
			ecosystems.NewPluginOptions().WithIncludeComponentMetadata(include))
		require.ErrorContains(t, err, "failed to detect Python version")
	}
}

// Without the flag the plugin keeps main's discovery and project identity.
func TestPlugin_FlagOffDiscoveryAndIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"requirements.txt", "node_modules/pkg/requirements.txt"} {
		writeFile(t, filepath.Join(dir, f), "alpha==1.0\n")
	}
	got, err := Plugin{}.discoverRequirementsFiles(t.Context(), logger.Nop(), dir, ecosystems.NewPluginOptions().WithAllProjects(true))
	require.NoError(t, err)
	assert.Len(t, got, 2, "node_modules is not excluded, as on main")

	fakePython(t, reportJSON(`{"url":"https://h/a.whl"}`))
	results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Nil(t, results[0].ProjectDescriptor.Identity.TargetFile, "identity unchanged from main")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func loggedCalls(t *testing.T, argsLog string) []string {
	t.Helper()
	b, err := os.ReadFile(argsLog)
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}
