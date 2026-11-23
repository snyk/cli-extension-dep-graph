//go:build !integration
// +build !integration

package pip

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/metadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

type recordingExecutor struct {
	name string
	args []string
}

func (r *recordingExecutor) Execute(_ context.Context, _, name string, args ...string) ([]byte, error) {
	r.name, r.args = name, args
	return []byte(`{"install":[]}`), nil
}

func TestGetInstallReport_PythonCommand(t *testing.T) {
	t.Run("--command runs pip as a module of that interpreter", func(t *testing.T) {
		exec := &recordingExecutor{}
		_, err := GetInstallReportWithCommand(t.Context(), nil, "requirements.txt", false, "python3.11", exec)
		require.NoError(t, err)
		assert.Equal(t, "python3.11", exec.name)
		assert.Equal(t, []string{"-m", "pip", "install", "--dry-run"}, exec.args[:4])
	})

	t.Run("without --command bare pip runs, as before", func(t *testing.T) {
		exec := &recordingExecutor{}
		_, err := GetInstallReportWithCommand(t.Context(), nil, "requirements.txt", false, "", exec)
		require.NoError(t, err)
		assert.Equal(t, "pip", exec.name)
		assert.Equal(t, "install", exec.args[0])
	})

	t.Run("the packages variant honours --command too", func(t *testing.T) {
		exec := &recordingExecutor{}
		_, err := GetInstallReportFromPackagesWithCommand(t.Context(), nil, []string{"requests"}, nil, false, "py", exec)
		require.NoError(t, err)
		assert.Equal(t, "py", exec.name)
		assert.Equal(t, []string{"-m", "pip", "install"}, exec.args[:3])
	})
}

// fakePython writes an interpreter stand-in that reports a version and,
// for `-m pip install`, prints report (or fails when report is empty). It
// records its working directory and arguments, one call per line, so tests
// can see how and where the plugin invoked it.
func fakePython(t *testing.T, report string) (cmd, argsLog string) {
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
	cmd = filepath.Join(dir, "fakepython")
	require.NoError(t, os.WriteFile(cmd, []byte(script), 0o600))
	require.NoError(t, os.Chmod(cmd, 0o700))
	return cmd, argsLog
}

func TestPlugin_PythonCommandAndComponentMetadata(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("alpha==1.0\n"), 0o600))
	cmd, argsLog := fakePython(t, reportJSON(`{"url":"https://files.example/alpha-1.0.whl","archive_info":{"hashes":{"sha256":"`+sha256Hex+`"}}}`))

	for _, include := range []bool{true, false} {
		opts := ecosystems.NewPluginOptions().WithPythonCommand(cmd).WithIncludeComponentMetadata(include)
		results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Error)
		assert.Equal(t, "3.12.1", results[0].ResolverMetadata.VersionBuildInfo[metadata.PythonVersion])
		assert.Equal(t, "requirements.txt", results[0].ProjectDescriptor.GetTargetFile())

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

	logged, err := os.ReadFile(argsLog)
	require.NoError(t, err)
	assert.Contains(t, string(logged), "--version\n")
	assert.Contains(t, string(logged), "-m pip install --dry-run")
}

// The pip plugin runs ahead of legacy when component metadata is requested,
// so under --file it must claim only requirements.txt; anything else is left
// for the plugin that owns it (pipenv, or snyk-python-plugin for setup.py and
// non-standard requirements names, which need --package-manager there).
func TestPlugin_TargetFileScoping(t *testing.T) {
	cmd, _ := fakePython(t, reportJSON(`{"url":"https://h/a.whl"}`))
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

			// Without the flag the plugin does not run ahead of legacy, so
			// it keeps processing whatever --file names, as before.
			opts := ecosystems.NewPluginOptions().WithPythonCommand(cmd).WithTargetFile(tt.file)
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
// directory; -r and -c are relative to the file. Under --file, or for a
// manifest at the root, that directory is the scan root, as when the CLI
// runs from it (`--file=deploy/requirements.txt` with `-e .` names the
// root project). A sub-manifest found by --all-projects resolves from its
// own directory. The version probe runs in the same place.
func TestPlugin_WorkingDirectory(t *testing.T) {
	for _, tt := range []struct {
		name    string
		opts    func(*ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions
		wantRel string
	}{
		{"--file uses the scan root", func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithTargetFile("svc/requirements.txt")
		}, "."},
		{"--all-projects sub-manifest uses its directory", func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithAllProjects(true)
		}, "svc"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "svc", "requirements.txt"), "-e .\n")
			cmd, argsLog := fakePython(t, reportJSON(""))

			_, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir,
				tt.opts(ecosystems.NewPluginOptions().WithPythonCommand(cmd)))
			require.NoError(t, err)

			want := filepath.Join(dir, tt.wantRel)
			calls := loggedCalls(t, argsLog)
			require.Len(t, calls, 2)
			assert.Equal(t, want, strings.SplitN(calls[0], " ", 2)[0], calls[0])
			assert.Equal(t, want, strings.SplitN(calls[1], " ", 2)[0], calls[1])
			assert.Contains(t, calls[1], " -m pip install")
		})
	}
}

// A relative --command names an interpreter under the scan root, as in
// snyk-python-plugin, which runs it with the root as its working directory.
func TestPlugin_RelativeCommandResolvesAgainstScanRoot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "proj", "requirements.txt"), "alpha==1.0\n")
	cmd, argsLog := fakePython(t, reportJSON(""))
	rootPython := filepath.Join(dir, ".venv", "bin", "python")
	require.NoError(t, os.MkdirAll(filepath.Dir(rootPython), 0o755))
	require.NoError(t, os.Symlink(cmd, rootPython))
	// A decoy in the manifest directory, which is the working directory.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "proj", ".venv", "bin"), 0o755))
	writeFile(t, filepath.Join(dir, "proj", ".venv", "bin", "python"), "#!/bin/sh\nexit 1\n")
	require.NoError(t, os.Chmod(filepath.Join(dir, "proj", ".venv", "bin", "python"), 0o700))

	opts := ecosystems.NewPluginOptions().WithPythonCommand(".venv/bin/python").WithTargetFile("proj/requirements.txt")
	results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Len(t, loggedCalls(t, argsLog), 2, "the root interpreter ran")
}

func TestGetPythonVersionForCommand_BadCommand(t *testing.T) {
	_, err := GetPythonVersionForCommand(filepath.Join(t.TempDir(), "nope"), t.TempDir())
	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, "SNYK-CLI-0004", snykErr.ErrorCode)
	assert.NotContains(t, snykErr.Title, "installation")
	assert.Contains(t, snykErr.Detail, "--command")
}

func TestPlugin_AllProjectsSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"requirements.txt", "node_modules/pkg/requirements.txt", ".build/requirements.txt"} {
		writeFile(t, filepath.Join(dir, f), "")
	}
	got, err := Plugin{}.discoverRequirementsFiles(t.Context(), logger.Nop(), dir, ecosystems.NewPluginOptions().WithAllProjects(true))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "requirements.txt", got[0].RelPath)
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

// Without --command the interpreter comes from PATH, probed and run in the
// same directory as with it. When none is found, that project fails on its own
// with its target file, rather than aborting the scan.
func TestPlugin_InterpreterFromPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "svc", "requirements.txt"), "alpha==1.0\n")
	cmd, argsLog := fakePython(t, reportJSON(`{"url":"https://h/a.whl"}`))
	bin := t.TempDir()
	require.NoError(t, os.Symlink(cmd, filepath.Join(bin, "python3")))
	require.NoError(t, os.Symlink(cmd, filepath.Join(bin, "pip"))) // bare pip runs without --command
	t.Setenv("PATH", bin+string(os.PathListSeparator)+"/bin")      // /bin for the stand-in's cat

	results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithTargetFile("svc/requirements.txt"))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	calls := loggedCalls(t, argsLog)
	require.Len(t, calls, 2)
	assert.True(t, strings.HasPrefix(calls[0], dir+" --version"), calls[0])
	assert.True(t, strings.HasPrefix(calls[1], dir+" install --dry-run"), calls[1])

	t.Setenv("PATH", t.TempDir())
	results, err = scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithTargetFile("svc/requirements.txt"))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	assert.Equal(t, "svc/requirements.txt", results[0].ProjectDescriptor.GetTargetFile())
}
