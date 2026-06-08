package swiftpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePackageName(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "conventional formatting",
			src: `// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "my-app",
    dependencies: []
)`,
			want: "my-app",
		},
		{
			name: "single line",
			src:  `let package = Package(name: "compact", dependencies: [])`,
			want: "compact",
		},
		{
			name: "extra whitespace",
			src:  `let package = Package(   name   :   "spacey"   )`,
			want: "spacey",
		},
		{
			name: "name with hyphens and underscores",
			src:  `Package(name: "my-cool_pkg-1")`,
			want: "my-cool_pkg-1",
		},
		{
			name: "no Package() call",
			src:  `// just a comment`,
			want: "",
		},
		{
			name: "Package without name argument",
			src:  `let package = Package(defaultLocalization: "en")`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parsePackageName([]byte(tt.src)))
		})
	}
}

func TestReadPackageManifest_Missing(t *testing.T) {
	_, err := readPackageManifest(t.TempDir())
	require.Error(t, err)
	// Wrapped in a typed UnprocessableFileError; the cause chain preserves
	// the underlying os.ErrNotExist for callers that need to detect it.
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadPackageManifest_Unparseable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, packageManifestFile),
		[]byte("// only a comment, no Package()"), 0o600))

	_, err := readPackageManifest(dir)
	require.Error(t, err)
}

func TestReadPackageManifest_Success(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, packageManifestFile),
		[]byte(`let package = Package(name: "ok", dependencies: [])`), 0o600))

	m, err := readPackageManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, "ok", m.Name)
}
