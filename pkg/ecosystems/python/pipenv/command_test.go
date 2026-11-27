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

// fakePython puts python3 and pip stand-ins first on PATH. Each reports a
// version and, for `install`, prints a report whose download_info names the
// archive pip picked for each package in pkgs. They record each invocation's
// working directory and arguments.
func fakePython(t *testing.T, pkgs ...string) (argsLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script interpreter stand-in")
	}
	if len(pkgs) == 0 {
		pkgs = []string{"alpha@1.0"}
	}
	items := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		name, version, _ := strings.Cut(p, "@")
		items = append(items, `{"metadata":{"name":"`+name+`","version":"`+version+`"},"requested":true,`+
			`"download_info":{"url":"https://files.example/`+name+`-`+version+`-py3-none-any.whl","archive_info":{"hashes":{"sha256":"`+sha256Hex+`"}}}}`)
	}
	report := `{"install":[` + strings.Join(items, ",") + `]}`
	dir := t.TempDir()
	argsLog = filepath.Join(dir, "args.log")
	script := "#!/bin/sh\necho \"$PWD $@\" >> '" + argsLog + "'\n" +
		"if [ \"$1\" = --version ]; then echo 'Python 3.12.1'; exit 0; fi\n" +
		"cat >/dev/null\necho '" + report + "'\n"
	for _, name := range []string{"python3", "pip"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0o600))
		require.NoError(t, os.Chmod(filepath.Join(dir, name), 0o700))
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/bin"+string(os.PathListSeparator)+"/usr/bin")
	return argsLog
}

func TestPlugin_ComponentMetadata(t *testing.T) {
	dir := pipenvProject(t)
	argsLog := fakePython(t)

	for _, include := range []bool{true, false} {
		opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(include)
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
	assert.Contains(t, string(logged), " install --dry-run")
}

func TestPlugin_TargetFileScoping(t *testing.T) {
	fakePython(t)
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
			opts := ecosystems.NewPluginOptions().WithTargetFile(tt.file)
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

// The same working-directory rule as the pip plugin. With the flag: pip runs
// in the scan root under --file and in the Pipfile's directory for an
// --all-projects sub-manifest, and the version probe runs in the scan root.
// Without it both run in the process's working directory, as before.
func TestPlugin_WorkingDirectory(t *testing.T) {
	for _, tt := range []struct {
		name    string
		flag    bool
		opts    func(*ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions
		wantRel string // relative to the scan root; "" means the process cwd
	}{
		{"flag on, --file uses the scan root", true, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithTargetFile("svc/Pipfile")
		}, "."},
		{"flag on, --all-projects sub-manifest uses its directory", true, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithAllProjects(true)
		}, "svc"},
		{"flag off, --file uses the process cwd", false, func(o *ecosystems.SCAPluginOptions) *ecosystems.SCAPluginOptions {
			return o.WithTargetFile("svc/Pipfile")
		}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.Rename(pipenvProject(t), filepath.Join(root, "svc")))
			argsLog := fakePython(t)

			results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), root,
				tt.opts(ecosystems.NewPluginOptions().WithIncludeComponentMetadata(tt.flag)))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)

			b, err := os.ReadFile(argsLog)
			require.NoError(t, err)
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			require.Len(t, calls, 2)
			cwd, err := os.Getwd()
			require.NoError(t, err)
			wantPip, wantProbe := cwd, cwd
			if tt.wantRel != "" {
				wantPip, wantProbe = filepath.Join(root, tt.wantRel), root
			}
			assert.Equal(t, wantProbe, strings.SplitN(calls[0], " ", 2)[0], calls[0])
			assert.Equal(t, wantPip, strings.SplitN(calls[1], " ", 2)[0], calls[1])
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
			argsLog := fakePython(t)

			opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(tt.flag)
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

// A Pipfile VCS entry is resolved by name from the index, so the archive pip
// reports is not the one the Pipfile names. It gets no labels; an index
// entry beside it keeps them.
func TestPlugin_VCSEntriesGetNoLabels(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile"), []byte(
		"[packages]\nsix = {git = \"https://github.com/benjaminp/six.git\", ref = \"1.16.0\"}\n"+
			"tool = {hg = \"https://hg.example/tool\"}\nalpha = \"==1.0\"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(`{"_meta":{},"default":{},"develop":{}}`), 0o600))
	fakePython(t, "six@1.17.0", "tool@2.0", "alpha@1.0")

	results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	labelled := map[string]bool{}
	for _, n := range results[0].DepGraph.Graph.Nodes {
		labelled[n.NodeID] = n.Info != nil && n.Info.Labels["hash:sha-256"] != ""
	}
	assert.Equal(t, map[string]bool{"root-node": false, "six@1.17.0": false, "tool@2.0": false, "alpha@1.0": true}, labelled)
}
