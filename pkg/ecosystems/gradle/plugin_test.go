//go:build !integration

package gradle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── relativeTargetFile ───────────────────────────────────────────────────────

func TestRelativeTargetFile(t *testing.T) {
	t.Run("returns filename when build file is directly inside dir", func(t *testing.T) {
		got := relativeTargetFile("/project", "/project/build.gradle")
		assert.Equal(t, "build.gradle", got)
	})

	t.Run("returns relative sub-path for a sub-project build file", func(t *testing.T) {
		got := relativeTargetFile("/project", "/project/app/build.gradle")
		assert.Equal(t, filepath.Join("app", "build.gradle"), got)
	})

	t.Run("returns relative path for kotlin build script", func(t *testing.T) {
		got := relativeTargetFile("/project", "/project/app/build.gradle.kts")
		assert.Equal(t, filepath.Join("app", "build.gradle.kts"), got)
	})

	t.Run("returns the same string when absFile equals dir/build.gradle.kts", func(t *testing.T) {
		got := relativeTargetFile("/project", "/project/build.gradle.kts")
		assert.Equal(t, "build.gradle.kts", got)
	})
}

// ── isBuildFile ───────────────────────────────────────────────────────────────

func TestIsBuildFile(t *testing.T) {
	buildFiles := []string{"build.gradle", "build.gradle.kts"}
	nonBuildFiles := []string{"settings.gradle", "settings.gradle.kts", "pom.xml", "requirements.txt", ""}

	for _, file := range buildFiles {
		t.Run(fmt.Sprintf("%s should be build file", file), func(t *testing.T) {
			assert.True(t, isBuildFile(file))
			assert.True(t, isBuildFile("/project/submodule/"+file)) // Test with path
		})
	}

	for _, file := range nonBuildFiles {
		t.Run(fmt.Sprintf("%s should not be build file", file), func(t *testing.T) {
			assert.False(t, isBuildFile(file))
		})
	}
}

// ── matchesSubProject ─────────────────────────────────────────────────────────

func TestMatchesSubProject(t *testing.T) {
	tests := []struct {
		projPath  string
		projName  string
		selector  string
		wantMatch bool
	}{
		// Exact path match
		{":app", "app", ":app", true},
		// Name match
		{":app", "app", "app", true},
		// Root project matched by name — matchesSubProject checks projName == selector
		{":", "root", "root", true},
		// Gradle project path with leading colon
		{":services:api", "api", ":services:api", true},
		// selector without leading colon matches path with colon prefix
		{":app", "app", "app", true},
		// No match
		{":app", "app", "lib", false},
		{":app", "app", ":lib", false},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			got := matchesSubProject(tt.projPath, tt.projName, tt.selector)
			assert.Equal(t, tt.wantMatch, got,
				"matchesSubProject(%q, %q, %q)", tt.projPath, tt.projName, tt.selector)
		})
	}
}

// ── discoverGradleFiles ───────────────────────────────────────────────────────

func TestDiscoverGradleFiles(t *testing.T) {
	p := Plugin{}
	ctx := context.Background()

	buildFiles := []string{"build.gradle", "build.gradle.kts"}

	for _, filename := range buildFiles {
		t.Run(fmt.Sprintf("finds %s in root when no options set", filename), func(t *testing.T) {
			dir := t.TempDir()
			buildFile := filepath.Join(dir, filename)
			require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))

			files, err := p.discoverGradleFiles(ctx, dir, &ecosystems.SCAPluginOptions{})
			require.NoError(t, err)
			require.Len(t, files, 1)
			assert.Equal(t, buildFile, files[0].Path)
			assert.Equal(t, filename, files[0].RelPath)
		})
	}

	t.Run("returns no files when no Gradle build file found", func(t *testing.T) {
		dir := t.TempDir()

		files, err := p.discoverGradleFiles(ctx, dir, &ecosystems.SCAPluginOptions{})
		require.NoError(t, err)
		assert.Empty(t, files)
	})

	targetFiles := []string{"build.gradle", "build.gradle.kts"}

	for _, filename := range targetFiles {
		t.Run(fmt.Sprintf("uses target file when it is a %s", filename), func(t *testing.T) {
			dir := t.TempDir()
			subDir := filepath.Join(dir, "app")
			require.NoError(t, os.Mkdir(subDir, 0o755))
			buildFile := filepath.Join(subDir, filename)
			require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))

			tf := filepath.Join("app", filename)
			opts := &ecosystems.SCAPluginOptions{
				Global: ecosystems.GlobalOptions{TargetFile: &tf},
			}

			files, err := p.discoverGradleFiles(ctx, dir, opts)
			require.NoError(t, err)
			require.Len(t, files, 1)
			assert.Equal(t, buildFile, files[0].Path)
		})
	}

	t.Run("returns no files when target file is not a Gradle build file", func(t *testing.T) {
		dir := t.TempDir()
		tf := "pom.xml"
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &tf},
		}

		files, err := p.discoverGradleFiles(ctx, dir, opts)
		require.NoError(t, err)
		assert.Empty(t, files)
	})

	invalidTargetFiles := []string{"settings.gradle", "settings.gradle.kts"}

	for _, filename := range invalidTargetFiles {
		t.Run(fmt.Sprintf("returns no files when %s is target file", filename), func(t *testing.T) {
			dir := t.TempDir()
			settingsFile := filepath.Join(dir, filename)
			require.NoError(t, os.WriteFile(settingsFile, []byte(""), 0o644))

			opts := &ecosystems.SCAPluginOptions{
				Global: ecosystems.GlobalOptions{TargetFile: &filename},
			}

			files, err := p.discoverGradleFiles(ctx, dir, opts)
			require.NoError(t, err)
			assert.Empty(t, files)
		})
	}

	t.Run("returns error when target file does not exist", func(t *testing.T) {
		dir := t.TempDir()
		tf := "build.gradle" // Gradle file name but doesn't exist
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &tf},
		}

		_, err := p.discoverGradleFiles(ctx, dir, opts)
		require.Error(t, err)
	})

	t.Run("--all-projects finds all gradle files recursively", func(t *testing.T) {
		dir := t.TempDir()

		// Create gradleProj1: has both settings.gradle and build.gradle
		proj1Dir := filepath.Join(dir, "gradleProj1")
		require.NoError(t, os.MkdirAll(proj1Dir, 0o755))
		proj1Settings := filepath.Join(proj1Dir, "settings.gradle")
		proj1Build := filepath.Join(proj1Dir, "build.gradle")
		require.NoError(t, os.WriteFile(proj1Settings, []byte(""), 0o644))
		require.NoError(t, os.WriteFile(proj1Build, []byte(""), 0o644))

		// Create sub-modules of gradleProj1
		module1Dir := filepath.Join(proj1Dir, "module1")
		require.NoError(t, os.MkdirAll(module1Dir, 0o755))
		module1Build := filepath.Join(module1Dir, "build.gradle")
		require.NoError(t, os.WriteFile(module1Build, []byte(""), 0o644))

		// Create gradleProj2: only has settings.gradle
		proj2Dir := filepath.Join(dir, "gradleProj2")
		require.NoError(t, os.MkdirAll(proj2Dir, 0o755))
		proj2Settings := filepath.Join(proj2Dir, "settings.gradle")
		require.NoError(t, os.WriteFile(proj2Settings, []byte(""), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{AllProjects: true},
		}

		files, err := p.discoverGradleFiles(ctx, dir, opts)
		require.NoError(t, err)

		// Should find all gradle files (discovery doesn't filter - deduplication happens at runtime)
		require.Len(t, files, 4)

		paths := make([]string, 0, len(files))
		for _, f := range files {
			paths = append(paths, f.Path)
		}
		assert.ElementsMatch(t, []string{proj1Build, proj1Settings, module1Build, proj2Settings}, paths)
	})

	t.Run("--all-projects includes both build and settings files", func(t *testing.T) {
		dir := t.TempDir()
		settingsFile := filepath.Join(dir, "settings.gradle")
		buildFile := filepath.Join(dir, "build.gradle")
		buildKtsFile := filepath.Join(dir, "build.gradle.kts")
		settingsKtsFile := filepath.Join(dir, "settings.gradle.kts")

		require.NoError(t, os.WriteFile(settingsFile, []byte(""), 0o644))
		require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))
		require.NoError(t, os.WriteFile(buildKtsFile, []byte(""), 0o644))
		require.NoError(t, os.WriteFile(settingsKtsFile, []byte(""), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{AllProjects: true},
		}

		files, err := p.discoverGradleFiles(ctx, dir, opts)
		require.NoError(t, err)
		require.Len(t, files, 4)

		paths := make([]string, 0, len(files))
		for _, f := range files {
			paths = append(paths, f.Path)
		}
		assert.ElementsMatch(t, []string{buildFile, buildKtsFile, settingsFile, settingsKtsFile}, paths)
	})

	settingsFiles := []string{"settings.gradle", "settings.gradle.kts"}

	for _, filename := range settingsFiles {
		t.Run(fmt.Sprintf("falls back to %s when no build files in root", filename), func(t *testing.T) {
			dir := t.TempDir()
			settingsFile := filepath.Join(dir, filename)
			require.NoError(t, os.WriteFile(settingsFile, []byte(""), 0o644))

			files, err := p.discoverGradleFiles(ctx, dir, &ecosystems.SCAPluginOptions{})
			require.NoError(t, err)
			require.Len(t, files, 1)
			assert.Equal(t, settingsFile, files[0].Path)
		})
	}
}

// ── isSettingsFile ──────────────────────────────────────────────────────────

func TestIsSettingsFile(t *testing.T) {
	settingsFiles := []string{"settings.gradle", "settings.gradle.kts"}
	buildFiles := []string{"build.gradle", "build.gradle.kts"}
	nonGradleFiles := []string{"pom.xml", "package.json", ""}

	for _, file := range settingsFiles {
		t.Run(fmt.Sprintf("%s should be settings file", file), func(t *testing.T) {
			assert.True(t, isSettingsFile(file))
			assert.True(t, isSettingsFile("/project/"+file)) // Test with path
		})
	}

	for _, file := range buildFiles {
		t.Run(fmt.Sprintf("%s should not be settings file", file), func(t *testing.T) {
			assert.False(t, isSettingsFile(file))
		})
	}

	for _, file := range nonGradleFiles {
		t.Run(fmt.Sprintf("%s should not be settings file", file), func(t *testing.T) {
			assert.False(t, isSettingsFile(file))
		})
	}
}

// ── resolveInitScript ─────────────────────────────────────────────────────────

func TestResolveInitScript(t *testing.T) {
	t.Run("always creates temp file with embedded script content", func(t *testing.T) {
		path, cleanup, err := resolveInitScript()
		require.NoError(t, err)
		require.NotEmpty(t, path)

		// File should exist and contain the embedded init script.
		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.NotEmpty(t, data)
		assert.Equal(t, embeddedInitScript, data)

		// After cleanup the temp file should be removed.
		cleanup()
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr), "temp init script should be removed by cleanup")
	})
}

// ── buildExtraArgs ───────────────────────────────────────────────────────────

func TestBuildExtraArgs(t *testing.T) {
	t.Run("returns empty args when no user init script provided", func(t *testing.T) {
		dir := t.TempDir()
		opts := &ecosystems.SCAPluginOptions{}

		args, err := buildExtraArgs(dir, opts)
		require.NoError(t, err)
		assert.Empty(t, args)
	})

	t.Run("adds user init script as --init-script flag when provided", func(t *testing.T) {
		dir := t.TempDir()
		userScript := filepath.Join(dir, "custom.gradle")
		require.NoError(t, os.WriteFile(userScript, []byte("// custom"), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: userScript},
		}

		args, err := buildExtraArgs(dir, opts)
		require.NoError(t, err)
		assert.Equal(t, []string{"--init-script", userScript}, args)
	})

	t.Run("resolves relative user init script path against project dir", func(t *testing.T) {
		dir := t.TempDir()
		userScript := filepath.Join(dir, "scripts", "custom.gradle")
		require.NoError(t, os.MkdirAll(filepath.Dir(userScript), 0o755))
		require.NoError(t, os.WriteFile(userScript, []byte("// custom"), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: "scripts/custom.gradle"},
		}

		args, err := buildExtraArgs(dir, opts)
		require.NoError(t, err)
		assert.Equal(t, []string{"--init-script", userScript}, args)
	})

	t.Run("returns error when user init script does not exist", func(t *testing.T) {
		dir := t.TempDir()
		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: "nonexistent.gradle"},
		}

		_, err := buildExtraArgs(dir, opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script not found")
		assert.Contains(t, err.Error(), "nonexistent.gradle")
	})

	t.Run("returns error when user init script is a directory", func(t *testing.T) {
		dir := t.TempDir()
		scriptDir := filepath.Join(dir, "scripts")
		require.NoError(t, os.Mkdir(scriptDir, 0o755))

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: scriptDir},
		}

		_, err := buildExtraArgs(dir, opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script is a directory")
	})
}
