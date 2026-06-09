package composer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadComposerLock_Valid(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, composerLockFile), []byte(`{
		"packages": [
			{"name":"guzzlehttp/guzzle","version":"7.8.0"},
			{"name":"psr/log","version":"3.0.0"}
		],
		"packages-dev": [
			{"name":"phpunit/phpunit","version":"10.5.0"}
		]
	}`), 0o600))

	lock, err := readComposerLock(tmp)
	require.NoError(t, err)
	require.NotNil(t, lock)
	assert.Len(t, lock.Packages, 2)
	assert.Len(t, lock.PackagesDev, 1)
}

func TestReadComposerLock_Missing(t *testing.T) {
	_, err := readComposerLock(t.TempDir())
	require.Error(t, err)
}

func TestReadComposerLock_InvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, composerLockFile),
		[]byte(`{not json`), 0o600))

	_, err := readComposerLock(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing")
}

func TestComposerLockShape_VersionMap(t *testing.T) {
	lock := &composerLockShape{
		Packages: []composerLockPackage{
			{Name: "guzzlehttp/guzzle", Version: "7.8.0"},
			{Name: "", Version: "ignored"}, // empty name should be filtered
		},
		PackagesDev: []composerLockPackage{
			{Name: "phpunit/phpunit", Version: "10.5.0"},
		},
	}

	m := lock.versionMap()
	assert.Equal(t, "7.8.0", m["guzzlehttp/guzzle"])
	assert.Equal(t, "10.5.0", m["phpunit/phpunit"])
	assert.NotContains(t, m, "")
	assert.Len(t, m, 2)
}

func TestComposerLockShape_VersionMap_Nil(t *testing.T) {
	var lock *composerLockShape
	assert.Nil(t, lock.versionMap())
}

func TestReadComposerJSON_Valid(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, composerJSONFile),
		[]byte(`{"name":"vendor/app","version":"2.5.0"}`), 0o600))

	pj, err := readComposerJSON(tmp)
	require.NoError(t, err)
	assert.Equal(t, "vendor/app", pj.Name)
	assert.Equal(t, "2.5.0", pj.Version)
}

func TestReadComposerJSON_Missing(t *testing.T) {
	pj, err := readComposerJSON(t.TempDir())
	require.NoError(t, err, "missing composer.json should be non-fatal")
	assert.Empty(t, pj.Name)
}

func TestReadComposerJSON_Invalid(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, composerJSONFile),
		[]byte(`{not json`), 0o600))

	_, err := readComposerJSON(tmp)
	require.Error(t, err)
}

func TestRootProjectName(t *testing.T) {
	tests := []struct {
		name string
		pj   *composerJSON
		dir  string
		want string
	}{
		{
			name: "uses composer.json name when present",
			pj:   &composerJSON{Name: "vendor/app"},
			dir:  "/tmp/somewhere",
			want: "vendor/app",
		},
		{
			name: "falls back to dir base when name is empty",
			pj:   &composerJSON{},
			dir:  "/tmp/my-project",
			want: "my-project",
		},
		{
			name: "nil composer.json falls back to dir",
			pj:   nil,
			dir:  "/tmp/another",
			want: "another",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rootProjectName(tt.pj, tt.dir))
		})
	}
}

func TestRootProjectVersion(t *testing.T) {
	assert.Equal(t, "1.2.3", rootProjectVersion(&composerJSON{Version: "1.2.3"}))
	assert.Equal(t, defaultVersion, rootProjectVersion(&composerJSON{}))
	assert.Equal(t, defaultVersion, rootProjectVersion(nil))
}
