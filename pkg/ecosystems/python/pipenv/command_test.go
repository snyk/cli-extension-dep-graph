//go:build !integration
// +build !integration

package pipenv

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var sha256Hex = strings.Repeat("ab", 32)

// pipenvProject writes a Pipfile and Pipfile.lock. The lock lists two hashes
// for alpha, as Pipfile.lock does for a package with several files: they name
// no file, so labels must come from the pip report instead.
func pipenvProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile"), []byte("[packages]\nalpha = \"==1.0\"\n"), 0o600))
	lock := `{"_meta":{"sources":[]},"default":{"alpha":{"version":"==1.0","hashes":["sha256:` +
		strings.Repeat("11", 32) + `","sha256:` + strings.Repeat("22", 32) + `"]}},"develop":{}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(lock), 0o600))
	return dir
}

// fakePython stands in for --command: it reports a version and, for
// `-m pip install`, prints a one-package report whose download_info names
// the archive pip picked. It records each invocation's arguments.
func fakePython(t *testing.T) (cmd, argsLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script interpreter stand-in")
	}
	dir := t.TempDir()
	argsLog = filepath.Join(dir, "args.log")
	report := `{"install":[{"metadata":{"name":"alpha","version":"1.0"},"requested":true,` +
		`"download_info":{"url":"https://files.example/alpha-1.0-py3-none-any.whl","archive_info":{"hashes":{"sha256":"` + sha256Hex + `"}}}}]}`
	script := "#!/bin/sh\necho \"$PWD $@\" >> '" + argsLog + "'\n" +
		"if [ \"$1\" = --version ]; then echo 'Python 3.12.1'; exit 0; fi\n" +
		"cat >/dev/null\necho '" + report + "'\n"
	cmd = filepath.Join(dir, "fakepython")
	require.NoError(t, os.WriteFile(cmd, []byte(script), 0o600))
	require.NoError(t, os.Chmod(cmd, 0o700))
	return cmd, argsLog
}

func TestPlugin_PythonCommandAndComponentMetadata(t *testing.T) {
	dir := pipenvProject(t)
	cmd, argsLog := fakePython(t)

	for _, include := range []bool{true, false} {
		opts := ecosystems.NewPluginOptions().WithPythonCommand(cmd).WithIncludeComponentMetadata(include)
		results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Error)

		var labels map[string]string
		for _, n := range results[0].DepGraph.Graph.Nodes {
			if n.NodeID == "alpha@1.0" && n.Info != nil {
				labels = n.Info.Labels
			}
		}
		if include {
			assert.Equal(t, map[string]string{
				"hash:sha-256":     sha256Hex,
				"distribution:url": "https://files.example/alpha-1.0-py3-none-any.whl",
			}, labels, "the hash of the file pip picked, not either Pipfile.lock hash")
		} else {
			assert.Nil(t, labels, "flag off: graph unchanged")
		}
	}

	logged, err := os.ReadFile(argsLog)
	require.NoError(t, err)
	assert.Contains(t, string(logged), "-m pip install --dry-run")
}

func TestPlugin_TargetFileScoping(t *testing.T) {
	cmd, _ := fakePython(t)
	for _, tt := range []struct {
		file  string
		claim bool
	}{
		{"Pipfile", true},
		{"Pipfile.lock", false},
		{"requirements.txt", false},
		{"setup.py", false},
	} {
		t.Run(tt.file, func(t *testing.T) {
			dir := pipenvProject(t)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("alpha==1.0\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "setup.py"), []byte(""), 0o600))

			// Without the flag --file is used as given, as before.
			opts := ecosystems.NewPluginOptions().WithPythonCommand(cmd).WithTargetFile(tt.file)
			results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
			require.NoError(t, err)
			require.Len(t, results, 1, "flag off: --file is processed whatever its name")

			results, err = scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts.WithIncludeComponentMetadata(true))
			require.NoError(t, err)
			if !tt.claim {
				assert.Empty(t, results)
				return
			}
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)
		})
	}
}

// The same working-directory rule as the pip plugin: the scan root under
// --file, the Pipfile's directory for an --all-projects sub-manifest.
func TestPlugin_WorkingDirectory(t *testing.T) {
	for _, tt := range []struct {
		name    string
		opts    func(*ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions
		wantRel string
	}{
		{"--file uses the scan root", func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithTargetFile("svc/Pipfile")
		}, "."},
		{"--all-projects sub-manifest uses its directory", func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithAllProjects(true)
		}, "svc"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.Rename(pipenvProject(t), filepath.Join(root, "svc")))
			cmd, argsLog := fakePython(t)

			results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), root,
				tt.opts(ecosystems.NewPluginOptions().WithPythonCommand(cmd)))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)

			b, err := os.ReadFile(argsLog)
			require.NoError(t, err)
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			require.Len(t, calls, 2)
			want := filepath.Join(root, tt.wantRel)
			assert.Equal(t, want, strings.SplitN(calls[0], " ", 2)[0], calls[0])
			assert.Equal(t, want, strings.SplitN(calls[1], " ", 2)[0], calls[1])
		})
	}
}

// A Pipfile path entry names a local project. Resolved by name, it installs
// an unrelated index package of the same name, with its hash. With component
// metadata requested, a present path is resolved from disk and a missing one
// (isolated builds copy only the Pipfile and its lock) is left out. Without
// the flag the old by-name resolution is kept; fixing it there is separate.
func TestPlugin_LocalPathEntries(t *testing.T) {
	bareUtils := regexp.MustCompile(` utils( [^@]|$)`)
	for _, tt := range []struct {
		name               string
		flag, present      bool
		wantDirect, wantBy bool
	}{
		{name: "flag off, path missing: resolved by name as before", wantBy: true},
		{name: "flag off, path present: resolved by name as before", present: true, wantBy: true},
		{name: "flag on, path present: resolved from disk", flag: true, present: true, wantDirect: true},
		{name: "flag on, path missing: left out, project still resolves", flag: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Not t.TempDir: the subtest name would put commas, which are
			// percent-encoded, into the expected URL.
			dir, err := os.MkdirTemp("", "pipenv")
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile"),
				[]byte("[packages]\nutils = {path = \"./utils\", editable = true}\nsix = \"==1.16.0\"\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"),
				[]byte(`{"_meta":{},"default":{"utils":{"editable":true,"path":"./utils"},"six":{"version":"==1.16.0"}},"develop":{}}`), 0o600))
			if tt.present {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "utils"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "utils", "pyproject.toml"), nil, 0o600))
			}
			cmd, argsLog := fakePython(t)

			opts := ecosystems.NewPluginOptions().WithPythonCommand(cmd).WithIncludeComponentMetadata(tt.flag)
			results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)

			b, err := os.ReadFile(argsLog)
			require.NoError(t, err)
			pipCall := strings.Split(strings.TrimSpace(string(b)), "\n")[1]
			assert.Equal(t, tt.wantDirect, strings.Contains(pipCall, " utils @ "+wantFileURL(filepath.Join(dir, "utils"))), pipCall)
			assert.Equal(t, tt.wantBy, bareUtils.MatchString(pipCall), pipCall)
			assert.Contains(t, pipCall, " six")
		})
	}
}

func TestPlugin_AllProjectsSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"Pipfile", "node_modules/pkg/Pipfile", ".build/Pipfile"} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), nil, 0o600))
	}
	got, err := Plugin{}.discoverPipfiles(t.Context(), logger.Nop(), dir, ecosystems.NewPluginOptions().WithAllProjects(true))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "Pipfile", got[0].RelPath)
}

func TestPlugin_MissingInterpreterFailsTheProject(t *testing.T) {
	dir := pipenvProject(t)
	opts := ecosystems.NewPluginOptions().WithPythonCommand(filepath.Join(t.TempDir(), "nope"))
	results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	var snykErr snyk_errors.Error
	require.ErrorAs(t, results[0].Error, &snykErr)
	assert.Contains(t, snykErr.Detail, "--command")
	assert.Equal(t, []string{"Pipfile"}, results[0].ProcessedFiles)
}
