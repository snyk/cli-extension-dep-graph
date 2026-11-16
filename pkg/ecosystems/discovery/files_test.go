//go:build !integration
// +build !integration

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupFiles creates test files in the given directory
func setupFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		fullPath := filepath.Join(root, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0644))
	}
}

func TestFindFiles_TargetFile(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte("test"), 0644))

	// Create subdirectory structure
	require.NoError(t, os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "subdir", "sub-requirements.txt"), []byte("test"), 0644))

	absoluteRootFile := filepath.Join(tmpDir, "requirements.txt")
	absoluteSubdirFile := filepath.Join(tmpDir, "subdir", "sub-requirements.txt")

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside-requirements.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("test"), 0644))

	outsideRelPath, err := filepath.Rel(tmpDir, outsideFile)
	require.NoError(t, err)

	tests := []struct {
		name        string
		targetFile  string
		exclude     string
		wantCount   int
		wantRelPath string
		wantErr     bool
	}{
		{"finds existing target file", "requirements.txt", "", 1, "requirements.txt", false},
		{"errors when not found", "missing.txt", "", 0, "", true},
		{"excludes when pattern matches", "requirements.txt", "*.txt", 0, "", false},
		{"finds in subdirectory", "subdir/sub-requirements.txt", "", 1, "subdir/sub-requirements.txt", false},
		{"finds absolute target file at root", absoluteRootFile, "", 1, "requirements.txt", false},
		{"finds absolute target file in subdirectory", absoluteSubdirFile, "", 1, "subdir/sub-requirements.txt", false},
		{"finds absolute target file outside root", outsideFile, "", 1, outsideRelPath, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []FindOption{WithTargetFile(tt.targetFile)}
			if tt.exclude != "" {
				opts = append(opts, WithExclude(tt.exclude))
			}

			results, err := FindFiles(context.Background(), logger.Nop(), tmpDir, opts...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				return
			}
			require.NoError(t, err)
			assert.Len(t, results, tt.wantCount)

			if tt.wantRelPath != "" && len(results) > 0 {
				assert.Equal(t, tt.wantRelPath, results[0].RelPath)
			}
		})
	}
}

func TestFindFiles_IncludeGlob(t *testing.T) {
	tmpDir := t.TempDir()
	setupFiles(t, tmpDir, map[string]string{
		"requirements.txt":         "test",
		"requirements-dev.txt":     "test",
		"setup.py":                 "test",
		"subdir/requirements.txt":  "test",
		"subdir/other.txt":         "test",
		"subdir2/requirements.txt": "test",
	})

	tests := []struct {
		name      string
		pattern   string
		wantCount int
	}{
		{"finds all matching pattern", "requirements*.txt", 4},
		{"finds simple pattern", "*.py", 1},
		{"returns empty when no match", "*.yml", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := FindFiles(context.Background(), logger.Nop(), tmpDir, WithInclude(tt.pattern))
			require.NoError(t, err)
			assert.Len(t, results, tt.wantCount)
		})
	}
}

func TestFindFiles_ExcludePattern(t *testing.T) {
	tmpDir := t.TempDir()
	setupFiles(t, tmpDir, map[string]string{
		"requirements.txt":                  "test",
		"node_modules/package.json":         "test",
		"node_modules/dep/requirements.txt": "test",
		".venv/requirements.txt":            "test",
		"subdir/requirements.txt":           "test",
	})

	t.Run("excludes files by name", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("*.json"),
			WithExclude("package.json"))
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("excludes directories by name", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("requirements.txt"),
			WithExclude("node_modules"))
		require.NoError(t, err)
		assert.Len(t, results, 3)
		for _, r := range results {
			assert.NotContains(t, r.RelPath, "node_modules")
		}
	})

	t.Run("excludes hidden directories", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("requirements.txt"),
			WithExclude(".*"))
		require.NoError(t, err)
		for _, r := range results {
			assert.NotContains(t, r.RelPath, ".venv")
		}
	})

	t.Run("multiple exclude patterns", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("requirements.txt"),
			WithExclude("node_modules"),
			WithExclude(".*"))
		require.NoError(t, err)
		for _, r := range results {
			assert.NotContains(t, r.RelPath, "node_modules")
			assert.NotContains(t, r.RelPath, ".venv")
		}
	})

	t.Run("WithExcludes variadic", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("requirements.txt"),
			WithExcludes("node_modules", ".*"))
		require.NoError(t, err)
		for _, r := range results {
			assert.NotContains(t, r.RelPath, "node_modules")
			assert.NotContains(t, r.RelPath, ".venv")
		}
	})
}

func TestFindFiles_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	// Create nested structure
	for i := 0; i < 100; i++ {
		subDir := filepath.Join(tmpDir, "dir", "nested", "path", "very", "deep")
		require.NoError(t, os.MkdirAll(subDir, 0755))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := FindFiles(ctx, logger.Nop(), tmpDir, WithInclude("*.txt"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestFindFiles_ValidationErrors(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		rootDir    string
		opts       []FindOption
		wantErrMsg string
	}{
		{"empty root directory", "", []FindOption{WithInclude("*.txt")}, "rootDir cannot be empty"},
		{"no search criteria", tmpDir, []FindOption{}, "at least one target file or include pattern must be specified"},
		{"invalid include pattern", tmpDir, []FindOption{WithInclude("[invalid")}, "invalid include pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FindFiles(context.Background(), logger.Nop(), tt.rootDir, tt.opts...)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

func TestFindFiles_MultipleTargetsAndGlobs(t *testing.T) {
	tmpDir := t.TempDir()
	setupFiles(t, tmpDir, map[string]string{
		"requirements.txt":        "test",
		"requirements-dev.txt":    "test",
		"setup.py":                "test",
		"pyproject.toml":          "test",
		"subdir/requirements.txt": "test",
		"subdir/setup.py":         "test",
	})

	tests := []struct {
		name      string
		opts      []FindOption
		wantCount int
	}{
		{
			"multiple target files chained",
			[]FindOption{WithTargetFile("requirements.txt"), WithTargetFile("setup.py")},
			2,
		},
		{
			"multiple target files variadic",
			[]FindOption{WithTargetFiles("requirements.txt", "setup.py", "pyproject.toml")},
			3,
		},
		{
			"multiple include globs chained",
			[]FindOption{WithInclude("*.py"), WithInclude("*.toml")},
			3,
		},
		{
			"multiple include globs variadic",
			[]FindOption{WithIncludes("*.py", "*.toml")},
			3,
		},
		{
			"combine targets and globs",
			[]FindOption{WithTargetFile("requirements.txt"), WithInclude("*.py")},
			3,
		},
		{
			"deduplicates overlapping results",
			[]FindOption{WithTargetFile("requirements.txt"), WithInclude("requirements*.txt")},
			3, // requirements.txt (deduplicated), requirements-dev.txt, subdir/requirements.txt
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := FindFiles(context.Background(), logger.Nop(), tmpDir, tt.opts...)
			require.NoError(t, err)
			assert.Len(t, results, tt.wantCount)
		})
	}

	// Test error case separately
	t.Run("errors on missing target file", func(t *testing.T) {
		_, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithTargetFile("missing.txt"),
			WithTargetFile("requirements.txt"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing.txt")
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestFindFiles_EdgeCases(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir, WithInclude("*.txt"))
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("only directories no files", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(tmpDir, "subdir1"), 0755))
		require.NoError(t, os.Mkdir(filepath.Join(tmpDir, "subdir2"), 0755))

		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir, WithInclude("*.txt"))
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("handles relative paths", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test"), 0644))

		wd, err := os.Getwd()
		require.NoError(t, err)
		relDir, err := filepath.Rel(wd, tmpDir)
		require.NoError(t, err)

		results, err := FindFiles(context.Background(), logger.Nop(), relDir, WithInclude("*.txt"))
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.True(t, filepath.IsAbs(results[0].Path), "path should be absolute")
	})
}

func relPaths(t *testing.T, results []FindResult) []string {
	t.Helper()
	paths := make([]string, 0, len(results))
	for _, r := range results {
		paths = append(paths, filepath.ToSlash(r.RelPath))
	}
	sort.Strings(paths)
	return paths
}

func TestFindFiles_MaxDepth(t *testing.T) {
	tmpDir := t.TempDir()
	setupFiles(t, tmpDir, map[string]string{
		"manifest.txt":       "test",
		"a/manifest.txt":     "test",
		"a/b/manifest.txt":   "test",
		"a/b/c/manifest.txt": "test",
	})

	all := []string{"a/b/c/manifest.txt", "a/b/manifest.txt", "a/manifest.txt", "manifest.txt"}

	tests := []struct {
		name     string
		maxDepth int
		want     []string
	}{
		{"depth 1 finds only files in the root", 1, []string{"manifest.txt"}},
		{"depth 2 also finds one directory down", 2, []string{"a/manifest.txt", "manifest.txt"}},
		{"depth 3 also finds two directories down", 3, []string{"a/b/manifest.txt", "a/manifest.txt", "manifest.txt"}},
		{"depth deeper than the tree finds everything", 10, all},
		// snyk/cli rejects --detection-depth<=0 before resolution runs, so a
		// non-positive value is treated as unset rather than as "root only".
		{"depth 0 means unlimited", 0, all},
		{"negative depth means unlimited", -1, all},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
				WithInclude("manifest.txt"),
				WithMaxDepth(tt.maxDepth))
			require.NoError(t, err)
			assert.Equal(t, tt.want, relPaths(t, results))
		})
	}

	t.Run("no depth option means unlimited", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("manifest.txt"))
		require.NoError(t, err)
		assert.Equal(t, all, relPaths(t, results))
	})

	t.Run("depth does not restrict an explicit target file", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithTargetFile("a/b/c/manifest.txt"),
			WithMaxDepth(1))
		require.NoError(t, err)
		assert.Equal(t, []string{"a/b/c/manifest.txt"}, relPaths(t, results))
	})
}

func TestFindFiles_MaxDepthWithExcludes(t *testing.T) {
	tmpDir := t.TempDir()
	setupFiles(t, tmpDir, map[string]string{
		"manifest.txt":                "test",
		"a/manifest.txt":              "test",
		"a/b/manifest.txt":            "test",
		"node_modules/manifest.txt":   "test",
		"a/node_modules/manifest.txt": "test",
		"skipme/manifest.txt":         "test",
		"a/skipme/manifest.txt":       "test",
	})

	t.Run("composes with WithCommonExcludes", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("manifest.txt"),
			WithCommonExcludes(),
			WithMaxDepth(3))
		require.NoError(t, err)
		assert.Equal(t, []string{
			"a/b/manifest.txt",
			"a/manifest.txt",
			"a/skipme/manifest.txt",
			"manifest.txt",
			"skipme/manifest.txt",
		}, relPaths(t, results))
	})

	t.Run("common excludes still apply when depth would allow them", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("manifest.txt"),
			WithCommonExcludes(),
			WithMaxDepth(2))
		require.NoError(t, err)
		assert.Equal(t, []string{"a/manifest.txt", "manifest.txt", "skipme/manifest.txt"}, relPaths(t, results))
	})

	t.Run("depth prunes deeper than the exclude patterns reach", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("manifest.txt"),
			WithExcludes("node_modules", "skipme"),
			WithMaxDepth(2))
		require.NoError(t, err)
		assert.Equal(t, []string{"a/manifest.txt", "manifest.txt"}, relPaths(t, results))
	})

	t.Run("excludes narrow results within the depth limit", func(t *testing.T) {
		results, err := FindFiles(context.Background(), logger.Nop(), tmpDir,
			WithInclude("manifest.txt"),
			WithCommonExcludes(),
			WithExclude("skipme"),
			WithMaxDepth(3))
		require.NoError(t, err)
		assert.Equal(t, []string{"a/b/manifest.txt", "a/manifest.txt", "manifest.txt"}, relPaths(t, results))
	})
}
