//go:build !integration
// +build !integration

package pipenv

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePipfile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantErr  bool
		validate func(t *testing.T, pf *Pipfile)
	}{
		{
			name: "basic pipfile with packages",
			content: `
[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
requests = "*"
flask = ">=2.0"

[dev-packages]
pytest = "*"

[requires]
python_version = "3.9"
`,
			wantErr: false,
			validate: func(t *testing.T, pf *Pipfile) {
				t.Helper()
				assert.Len(t, pf.Source, 1)
				assert.Equal(t, "pypi", pf.Source[0].Name)
				assert.Equal(t, "https://pypi.org/simple", pf.Source[0].URL)
				assert.True(t, pf.Source[0].Verify)

				assert.Len(t, pf.Packages, 2)
				assert.Equal(t, "*", pf.Packages["requests"])
				assert.Equal(t, ">=2.0", pf.Packages["flask"])

				assert.Len(t, pf.DevPkgs, 1)
				assert.Equal(t, "*", pf.DevPkgs["pytest"])

				assert.Equal(t, "3.9", pf.Requires.PythonVersion)
			},
		},
		{
			name: "pipfile with complex package specs",
			content: `
[packages]
requests = {version = ">=2.0", extras = ["security"]}
mypackage = {git = "https://github.com/user/repo.git", ref = "main"}
localpackage = {path = "./local", editable = true}
`,
			wantErr: false,
			validate: func(t *testing.T, pf *Pipfile) {
				t.Helper()
				assert.Len(t, pf.Packages, 3)

				// Check complex version spec
				reqSpec, ok := pf.Packages["requests"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, ">=2.0", reqSpec["version"])

				// Check git spec
				gitSpec, ok := pf.Packages["mypackage"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "https://github.com/user/repo.git", gitSpec["git"])
				assert.Equal(t, "main", gitSpec["ref"])

				// Check path spec
				pathSpec, ok := pf.Packages["localpackage"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "./local", pathSpec["path"])
				assert.Equal(t, true, pathSpec["editable"])
			},
		},
		{
			name:    "empty pipfile",
			content: "",
			wantErr: false,
			validate: func(t *testing.T, pf *Pipfile) {
				t.Helper()
				assert.Empty(t, pf.Packages)
				assert.Empty(t, pf.DevPkgs)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			pipfilePath := filepath.Join(tmpDir, "Pipfile")
			err := os.WriteFile(pipfilePath, []byte(tt.content), 0o600)
			require.NoError(t, err)

			// Parse
			pf, err := ParsePipfile(pipfilePath)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			tt.validate(t, pf)
		})
	}
}

func TestMatchesPlatformMarker(t *testing.T) {
	currentPlatform := getCurrentPlatform()

	tests := []struct {
		name     string
		marker   string
		expected bool
	}{
		{
			name:     "win32 marker on current platform",
			marker:   "sys_platform == 'win32'",
			expected: currentPlatform == "win32",
		},
		{
			name:     "darwin marker on current platform",
			marker:   "sys_platform == 'darwin'",
			expected: currentPlatform == "darwin",
		},
		{
			name:     "linux marker on current platform",
			marker:   "sys_platform == 'linux'",
			expected: currentPlatform == "linux",
		},
		{
			name:     "not win32 marker",
			marker:   "sys_platform != 'win32'",
			expected: currentPlatform != "win32",
		},
		{
			name:     "double quotes",
			marker:   "sys_platform == \"win32\"",
			expected: currentPlatform == "win32",
		},
		{
			name:     "unknown marker returns true",
			marker:   "python_version >= '3.8'",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPlatformMarker(tt.marker)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePipfile_FileNotFound(t *testing.T) {
	_, err := ParsePipfile("/nonexistent/path/Pipfile")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read Pipfile")
}

func TestParsePipfile_InvalidTOML(t *testing.T) {
	tmpDir := t.TempDir()
	pipfilePath := filepath.Join(tmpDir, "Pipfile")
	err := os.WriteFile(pipfilePath, []byte("invalid toml [[["), 0o600)
	require.NoError(t, err)

	_, err = ParsePipfile(pipfilePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse Pipfile")
}

func TestPipfile_ToPackageNames(t *testing.T) {
	tests := []struct {
		name           string
		pipfile        *Pipfile
		includeDevDeps bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "simple packages without versions",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "==2.31.0",
					"flask":    ">=2.0",
					"django":   "*",
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests", "flask", "django"},
		},
		{
			name: "packages with extras",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": map[string]interface{}{
						"version": ">=2.0",
						"extras":  []interface{}{"security", "socks"},
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests[security,socks]"},
		},
		{
			name: "dev packages excluded by default",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "*",
				},
				DevPkgs: map[string]interface{}{
					"pytest": "*",
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests"},
			wantNotContain: []string{"pytest"},
		},
		{
			name: "dev packages included when requested",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "*",
				},
				DevPkgs: map[string]interface{}{
					"pytest": "*",
				},
			},
			includeDevDeps: true,
			wantContains:   []string{"requests", "pytest"},
		},
		{
			name: "git dependencies return name only",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"mypackage": map[string]interface{}{
						"git": "https://github.com/user/repo.git",
						"ref": "main",
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"mypackage"},
		},
		{
			name: "path dependencies return name only",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"localpackage": map[string]interface{}{
						"path":     "./local",
						"editable": true,
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"localpackage"},
		},
		{
			name: "platform markers filter packages",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "*",
					"pywin32": map[string]interface{}{
						"version": "==306",
						"markers": "sys_platform == 'win32'",
					},
				},
			},
			includeDevDeps: false,
			wantContains: func() []string {
				if getCurrentPlatform() == "win32" {
					return []string{"requests", "pywin32"}
				}
				return []string{"requests"}
			}(),
			wantNotContain: func() []string {
				if getCurrentPlatform() == "win32" {
					return nil
				}
				return []string{"pywin32"}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := tt.pipfile.ToPackageNames(tt.includeDevDeps)

			for _, want := range tt.wantContains {
				assert.Contains(t, names, want, "should contain %s", want)
			}
			for _, notWant := range tt.wantNotContain {
				assert.NotContains(t, names, notWant, "should not contain %s", notWant)
			}
		})
	}
}

// ToRequirements is ToPackageNames for the dry run: path and file entries
// become PEP 508 direct references, so pip builds them from disk (or the
// given URL) instead of resolving their name from an index.
func TestPipfile_ToRequirements(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("expected file URLs are written for POSIX paths")
	}
	dir := t.TempDir()
	for _, d := range []string{"utils", "abs", "extra", "dev", "a;b c+&%@"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, d), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, d, "pyproject.toml"), nil, 0o600))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "wheels"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wheels", "w-1.0-py3-none-any.whl"), nil, 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "notaproject"), 0o755))
	pipfile := &Pipfile{
		Packages: map[string]interface{}{
			"requests": "==2.31.0",
			"odd":      map[string]interface{}{"path": "a;b c+&%@"},
			"missing":  map[string]interface{}{"path": "./gone"},
			"gonefile": map[string]interface{}{"file": "./gone.whl"},
			"bare":     map[string]interface{}{"path": "notaproject"},
			"utils":    map[string]interface{}{"path": "./utils", "editable": true},
			"absolute": map[string]interface{}{"path": filepath.Join(dir, "abs")},
			"wheel":    map[string]interface{}{"file": "wheels/w-1.0-py3-none-any.whl"},
			"remote":   map[string]interface{}{"file": "https://files.example/remote-1.0.tar.gz"},
			"extra":    map[string]interface{}{"path": "extra", "extras": []interface{}{"cli"}},
			"flask":    map[string]interface{}{"version": ">=2", "extras": []interface{}{"async"}},
			"elsewhere": map[string]interface{}{
				"path": "./elsewhere", "markers": "sys_platform == 'no-such-platform' and sys_platform != '" + getCurrentPlatform() + "'",
			},
		},
		DevPkgs: map[string]interface{}{"devlocal": map[string]interface{}{"path": "dev"}},
	}

	got, dropped := pipfile.ToRequirements(false, dir)
	assert.ElementsMatch(t, []string{"missing", "gonefile", "bare"}, dropped,
		"a path with no project and a file that does not exist are left out")
	assert.ElementsMatch(t, []string{
		// Characters PEP 508 or URL parsing would misread are percent-encoded:
		// ";" would start a marker, " " end the URL.
		"odd @ " + wantFileURL(dir) + "/a%3Bb%20c%2B%26%25%40",
		"requests",
		"utils @ " + wantFileURL(filepath.Join(dir, "utils")),
		"absolute @ " + wantFileURL(filepath.Join(dir, "abs")),
		"wheel @ " + wantFileURL(filepath.Join(dir, "wheels", "w-1.0-py3-none-any.whl")),
		"remote @ https://files.example/remote-1.0.tar.gz",
		"extra[cli] @ " + wantFileURL(filepath.Join(dir, "extra")),
		"flask[async]",
	}, got)

	withDev, _ := pipfile.ToRequirements(true, dir)
	assert.Contains(t, withDev, "devlocal @ "+wantFileURL(filepath.Join(dir, "dev")))
}

// wantFileURL is the RFC 8089 form pip accepts in a direct reference.
func wantFileURL(path string) string { return "file://" + path }

// Without the component-metadata flag, a file entry resolves by name with its
// extras, exactly as before the flag existed.
func TestPipfile_ToPackageNames_FileEntryKeepsExtras(t *testing.T) {
	p := &Pipfile{Packages: map[string]interface{}{
		"pkg": map[string]interface{}{"file": "https://files.example/pkg-1.0.tar.gz", "extras": []interface{}{"cli"}},
	}}
	assert.Equal(t, []string{"pkg[cli]"}, p.ToPackageNames(false))
}
