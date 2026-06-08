package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFixture drops a package.json + package-lock.json pair into a tmp dir.
// Pass "" for either to omit it (used by missing-file tests).
func writeFixture(t *testing.T, dir, pkgJSON, lockJSON string) {
	t.Helper()
	if pkgJSON != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, packageJSONFile), []byte(pkgJSON), 0o600))
	}
	if lockJSON != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, packageLockFile), []byte(lockJSON), 0o600))
	}
}

func TestReadWorkspacePaths(t *testing.T) {
	tests := []struct {
		name     string
		pkgJSON  string
		lockfile string
		want     map[string]string
	}{
		{
			name: "named workspace via link entry",
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/*"]
			}`,
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
			// npm omits the embedded name when the workspace's name matches
			// the directory basename — regression test for the missing-name case.
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/*"]
			}`,
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
			name: "file: dep is NOT a workspace despite having a link entry",
			// The whole reason we cross-check against package.json: link
			// entries also appear for `"foo": "file:./local"` dependencies.
			// Without the workspaces-field check we'd misclassify these.
			pkgJSON: `{
				"name": "root",
				"dependencies": {"shared": "file:./some-local"}
			}`,
			lockfile: `{
				"packages": {
					"": {"name": "root"},
					"node_modules/shared": {"resolved": "some-local", "link": true}
				}
			}`,
			want: map[string]string{},
		},
		{
			name: "workspaces declared in object form",
			pkgJSON: `{
				"name": "root",
				"workspaces": {"packages": ["apps/*"]}
			}`,
			lockfile: `{
				"packages": {
					"node_modules/web": {"resolved": "apps/web", "link": true}
				}
			}`,
			want: map[string]string{"web": "apps/web"},
		},
		{
			name: "exact path workspace pattern (no glob)",
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/a", "packages/b"]
			}`,
			lockfile: `{
				"packages": {
					"node_modules/a": {"resolved": "packages/a", "link": true},
					"node_modules/b": {"resolved": "packages/b", "link": true},
					"node_modules/c": {"resolved": "packages/c", "link": true}
				}
			}`,
			// c isn't listed → filtered out as a file: dep.
			want: map[string]string{
				"a": "packages/a",
				"b": "packages/b",
			},
		},
		{
			name: "no workspaces declared",
			pkgJSON: `{
				"name": "root"
			}`,
			lockfile: `{
				"packages": {
					"node_modules/debug": {"version": "4.4.3"}
				}
			}`,
			want: map[string]string{},
		},
		{
			name: "scoped name via link entry",
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/*"]
			}`,
			lockfile: `{
				"packages": {
					"node_modules/@acme/utils": {"resolved": "packages/utils", "link": true}
				}
			}`,
			want: map[string]string{"@acme/utils": "packages/utils"},
		},
		{
			name: "link entry without resolved is ignored",
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/*"]
			}`,
			lockfile: `{
				"packages": {
					"node_modules/dangling": {"link": true}
				}
			}`,
			want: map[string]string{},
		},
		{
			name: "absolute resolved path is ignored (defensive)",
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/*"]
			}`,
			lockfile: `{
				"packages": {
					"node_modules/abs": {"resolved": "/etc/passwd", "link": true}
				}
			}`,
			want: map[string]string{},
		},
		{
			name: "malformed lockfile returns empty map",
			pkgJSON: `{
				"name": "root",
				"workspaces": ["packages/*"]
			}`,
			lockfile: `{not json`,
			want:     map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, tt.pkgJSON, tt.lockfile)

			got := readWorkspacePaths(dir)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadWorkspacePaths_MissingFiles(t *testing.T) {
	got := readWorkspacePaths(t.TempDir())
	assert.Equal(t, map[string]string{}, got, "missing files should return empty map, not nil")
}
