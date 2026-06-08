package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadWorkspacePaths(t *testing.T) {
	tests := []struct {
		name     string
		lockfile string
		want     map[string]string
	}{
		{
			name: "named workspace via link entry",
			lockfile: `{
				"packages": {
					"": {"name": "root", "version": "1.0.0"},
					"node_modules/@workspace/logger": {"resolved": "packages/logger", "link": true},
					"packages/logger": {"name": "@workspace/logger", "version": "1.0.0"}
				}
			}`,
			want: map[string]string{"@workspace/logger": "packages/logger"},
		},
		{
			name: "anonymous workspace (no name field on packages/X entry)",
			// This is the shape npm emits when the workspace's name is just
			// the directory basename — the link entry is the only thing that
			// names it. Regression test for the missing-name case.
			lockfile: `{
				"packages": {
					"": {"name": "root", "version": "1.0.0"},
					"node_modules/a": {"resolved": "packages/a", "link": true},
					"node_modules/b": {"resolved": "packages/b", "link": true},
					"packages/a": {"version": "1.0.0"},
					"packages/b": {"version": "1.0.0"}
				}
			}`,
			want: map[string]string{
				"a": "packages/a",
				"b": "packages/b",
			},
		},
		{
			name: "no workspaces",
			lockfile: `{
				"packages": {
					"": {"name": "root", "version": "1.0.0"},
					"node_modules/debug": {"version": "4.4.3"}
				}
			}`,
			want: map[string]string{},
		},
		{
			name: "scoped name via link entry",
			lockfile: `{
				"packages": {
					"node_modules/@acme/utils": {"resolved": "packages/utils", "link": true}
				}
			}`,
			want: map[string]string{"@acme/utils": "packages/utils"},
		},
		{
			name: "link entry without resolved is ignored",
			lockfile: `{
				"packages": {
					"node_modules/dangling": {"link": true}
				}
			}`,
			want: map[string]string{},
		},
		{
			name: "absolute resolved path is ignored (defensive)",
			lockfile: `{
				"packages": {
					"node_modules/abs": {"resolved": "/etc/passwd", "link": true}
				}
			}`,
			want: map[string]string{},
		},
		{
			name:     "malformed lockfile returns nil-as-empty",
			lockfile: `{not json`,
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, packageLockFile), []byte(tt.lockfile), 0o600))

			got := readWorkspacePaths(dir)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadWorkspacePaths_MissingLockfile(t *testing.T) {
	got := readWorkspacePaths(t.TempDir())
	assert.Nil(t, got, "missing lockfile should return nil, not error")
}
