package pipenv

import (
	"os"
	"path/filepath"
	"strings"
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

func TestPipfile_ToRequirements(t *testing.T) {
	tests := []struct {
		name           string
		pipfile        *Pipfile
		includeDevDeps bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "simple packages",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "*",
					"flask":    ">=2.0",
				},
				DevPkgs: map[string]interface{}{
					"pytest": "*",
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests", "flask>=2.0"},
			wantNotContain: []string{"pytest"},
		},
		{
			name: "include dev deps",
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
			name: "complex version spec",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": map[string]interface{}{
						"version": ">=2.0",
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests>=2.0"},
		},
		{
			name: "package with extras",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": map[string]interface{}{
						"version": ">=2.0",
						"extras":  []interface{}{"security", "socks"},
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests[security,socks]>=2.0"},
		},
		{
			name: "git dependency",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"mypackage": map[string]interface{}{
						"git": "https://github.com/user/repo.git",
						"ref": "main",
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"mypackage @ git+https://github.com/user/repo.git@main"},
		},
		{
			name: "editable path dependency",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"localpackage": map[string]interface{}{
						"path":     "./local",
						"editable": true,
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"-e ./local"},
		},
		{
			name: "compound version constraints",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"django":   ">=2.0,<=3.0",
					"requests": ">=2.25.0,<3.0.0",
					"flask":    "~=2.0",
					"numpy":    "!=1.19.0",
				},
			},
			includeDevDeps: false,
			wantContains: []string{
				"django>=2.0,<=3.0",
				"requests>=2.25.0,<3.0.0",
				"flask~=2.0",
				"numpy!=1.19.0",
			},
		},
		{
			name: "complex spec with compound version constraints",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": map[string]interface{}{
						"version": ">=2.0,<=3.0",
						"extras":  []interface{}{"security"},
					},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests[security]>=2.0,<=3.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqs := tt.pipfile.ToRequirements(tt.includeDevDeps)

			for _, want := range tt.wantContains {
				assert.Contains(t, reqs, want, "should contain %s", want)
			}
			for _, notWant := range tt.wantNotContain {
				assert.NotContains(t, reqs, notWant, "should not contain %s", notWant)
			}
		})
	}
}

func TestPipfile_ToRequirements_PlatformMarkers(t *testing.T) {
	currentPlatform := getCurrentPlatform()

	tests := []struct {
		name           string
		pipfile        *Pipfile
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "skip windows package on non-windows",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "*",
					"pywin32": map[string]interface{}{
						"version": "==306",
						"markers": "sys_platform == 'win32'",
					},
				},
			},
			wantContains: []string{"requests"},
			wantNotContain: func() []string {
				if currentPlatform == "win32" {
					return nil // On Windows, pywin32 should be included
				}
				return []string{"pywin32"}
			}(),
		},
		{
			name: "skip darwin package on non-darwin",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"requests": "*",
					"pyobjc": map[string]interface{}{
						"version": ">=9.0",
						"markers": "sys_platform == 'darwin'",
					},
				},
			},
			wantContains: []string{"requests"},
			wantNotContain: func() []string {
				if currentPlatform == "darwin" {
					return nil // On macOS, pyobjc should be included
				}
				return []string{"pyobjc"}
			}(),
		},
		{
			name: "include package with != marker when not on that platform",
			pipfile: &Pipfile{
				Packages: map[string]interface{}{
					"uvloop": map[string]interface{}{
						"version": ">=0.17",
						"markers": "sys_platform != 'win32'",
					},
				},
			},
			wantContains: func() []string {
				if currentPlatform != "win32" {
					return []string{"uvloop>=0.17"}
				}
				return nil
			}(),
			wantNotContain: func() []string {
				if currentPlatform == "win32" {
					return []string{"uvloop"}
				}
				return nil
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqs := tt.pipfile.ToRequirements(false)

			for _, want := range tt.wantContains {
				assert.Contains(t, reqs, want, "should contain %s", want)
			}
			for _, notWant := range tt.wantNotContain {
				found := false
				for _, req := range reqs {
					if strings.Contains(req, notWant) {
						found = true
						break
					}
				}
				assert.False(t, found, "should not contain %s, got %v", notWant, reqs)
			}
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
