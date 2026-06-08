package modules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadModulePath(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "bare",
			content: "module example.com/foo\n\ngo 1.21\n",
			want:    "example.com/foo",
		},
		{
			name:    "quoted",
			content: "module \"example.com/foo\"\n",
			want:    "example.com/foo",
		},
		{
			name:    "with line comment",
			content: "module example.com/foo // a project\n",
			want:    "example.com/foo",
		},
		{
			name:    "block form",
			content: "module (\n    example.com/foo\n)\n",
			want:    "example.com/foo",
		},
		{
			name:    "leading comment",
			content: "// header\nmodule example.com/foo\n",
			want:    "example.com/foo",
		},
		{
			name:    "no module directive",
			content: "go 1.21\n",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "go.mod")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			got, err := readModulePath(path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadModulePath_MissingFile(t *testing.T) {
	_, err := readModulePath(filepath.Join(t.TempDir(), "no-such-file"))
	assert.Error(t, err)
}

func TestReadWorkspaceDirs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "single inline",
			content: "go 1.21\n\nuse ./foo\n",
			want:    []string{"foo"},
		},
		{
			name:    "block form",
			content: "go 1.21\n\nuse (\n    ./foo\n    ./bar\n)\n",
			want:    []string{"foo", "bar"},
		},
		{
			name:    "quoted entries",
			content: "use (\n    \"./foo\"\n    \"./bar baz\"\n)\n",
			want:    []string{"foo", "bar baz"},
		},
		{
			name:    "with comments",
			content: "// header\nuse (\n    // member\n    ./foo\n)\n",
			want:    []string{"foo"},
		},
		{
			name:    "no use directive",
			content: "go 1.21\n",
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "go.work")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			got, err := readWorkspaceDirs(path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadWorkspaceDirs_MissingFileNoError(t *testing.T) {
	got, err := readWorkspaceDirs(filepath.Join(t.TempDir(), "no-go-work"))
	require.NoError(t, err)
	assert.Nil(t, got)
}
