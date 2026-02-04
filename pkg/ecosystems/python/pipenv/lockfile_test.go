package pipenv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePipfileLock(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantErr  bool
		validate func(t *testing.T, lf *PipfileLock)
	}{
		{
			name: "basic lockfile",
			content: `{
				"_meta": {
					"hash": {"sha256": "abc123"},
					"sources": [
						{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}
					],
					"requires": {"python_version": "3.9"}
				},
				"default": {
					"requests": {"version": "==2.28.0", "hashes": ["sha256:abc"]},
					"urllib3": {"version": "==1.26.0", "hashes": ["sha256:def"]}
				},
				"develop": {
					"pytest": {"version": "==7.0.0", "hashes": ["sha256:ghi"]}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, lf *PipfileLock) {
				t.Helper()
				assert.Equal(t, "abc123", lf.Meta.Hash.Sha256)
				assert.Len(t, lf.Meta.Sources, 1)
				assert.Equal(t, "3.9", lf.Meta.Requires.PythonVersion)

				assert.Len(t, lf.Default, 2)
				assert.Equal(t, "==2.28.0", lf.Default["requests"].Version)
				assert.Equal(t, "==1.26.0", lf.Default["urllib3"].Version)

				assert.Len(t, lf.Develop, 1)
				assert.Equal(t, "==7.0.0", lf.Develop["pytest"].Version)
			},
		},
		{
			name: "lockfile with git dependency",
			content: `{
				"_meta": {"hash": {"sha256": "abc"}, "sources": [], "requires": {}},
				"default": {
					"mypackage": {"git": "https://github.com/user/repo.git", "ref": "abc123"}
				},
				"develop": {}
			}`,
			wantErr: false,
			validate: func(t *testing.T, lf *PipfileLock) {
				t.Helper()
				pkg := lf.Default["mypackage"]
				assert.Equal(t, "https://github.com/user/repo.git", pkg.Git)
				assert.Equal(t, "abc123", pkg.Ref)
			},
		},
		{
			name: "empty lockfile",
			content: `{
				"_meta": {"hash": {"sha256": ""}, "sources": [], "requires": {}},
				"default": {},
				"develop": {}
			}`,
			wantErr: false,
			validate: func(t *testing.T, lf *PipfileLock) {
				t.Helper()
				assert.Empty(t, lf.Default)
				assert.Empty(t, lf.Develop)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			lockfilePath := filepath.Join(tmpDir, "Pipfile.lock")
			err := os.WriteFile(lockfilePath, []byte(tt.content), 0o600)
			require.NoError(t, err)

			lf, err := ParsePipfileLock(lockfilePath)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			tt.validate(t, lf)
		})
	}
}

func TestPipfileLock_ToConstraints(t *testing.T) {
	tests := []struct {
		name           string
		lockfile       *PipfileLock
		includeDevDeps bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "basic constraints",
			lockfile: &PipfileLock{
				Default: map[string]LockedPackage{
					"requests": {Version: "==2.28.0"},
					"urllib3":  {Version: "==1.26.0"},
				},
				Develop: map[string]LockedPackage{
					"pytest": {Version: "==7.0.0"},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests==2.28.0", "urllib3==1.26.0"},
			wantNotContain: []string{"pytest==7.0.0"},
		},
		{
			name: "include dev deps",
			lockfile: &PipfileLock{
				Default: map[string]LockedPackage{
					"requests": {Version: "==2.28.0"},
				},
				Develop: map[string]LockedPackage{
					"pytest": {Version: "==7.0.0"},
				},
			},
			includeDevDeps: true,
			wantContains:   []string{"requests==2.28.0", "pytest==7.0.0"},
		},
		{
			name: "skip git dependencies",
			lockfile: &PipfileLock{
				Default: map[string]LockedPackage{
					"requests":  {Version: "==2.28.0"},
					"mypackage": {Git: "https://github.com/user/repo.git", Ref: "main"},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests==2.28.0"},
			wantNotContain: []string{"mypackage"},
		},
		{
			name: "skip path dependencies",
			lockfile: &PipfileLock{
				Default: map[string]LockedPackage{
					"requests":     {Version: "==2.28.0"},
					"localpackage": {Path: "./local"},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"requests==2.28.0"},
			wantNotContain: []string{"localpackage"},
		},
		{
			name: "normalize package names",
			lockfile: &PipfileLock{
				Default: map[string]LockedPackage{
					"My_Package": {Version: "==1.0.0"},
				},
			},
			includeDevDeps: false,
			wantContains:   []string{"my-package==1.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraints := tt.lockfile.ToConstraints(tt.includeDevDeps)

			for _, want := range tt.wantContains {
				assert.Contains(t, constraints, want, "should contain %s", want)
			}
			for _, notWant := range tt.wantNotContain {
				found := false
				for _, c := range constraints {
					if c == notWant {
						found = true
						break
					}
				}
				assert.False(t, found, "should not contain %s", notWant)
			}
		})
	}
}

func TestParsePipfileLock_FileNotFound(t *testing.T) {
	_, err := ParsePipfileLock("/nonexistent/path/Pipfile.lock")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read Pipfile.lock")
}

func TestParsePipfileLock_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	lockfilePath := filepath.Join(tmpDir, "Pipfile.lock")
	err := os.WriteFile(lockfilePath, []byte("invalid json {{{"), 0o600)
	require.NoError(t, err)

	_, err = ParsePipfileLock(lockfilePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse Pipfile.lock")
}
