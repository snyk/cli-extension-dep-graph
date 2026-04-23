//go:build !integration

package gradle

import (
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
	assert.True(t, isBuildFile("build.gradle"))
	assert.True(t, isBuildFile("build.gradle.kts"))
	assert.True(t, isBuildFile("/project/submodule/build.gradle"))
	assert.True(t, isBuildFile("/project/submodule/build.gradle.kts"))
	assert.False(t, isBuildFile("settings.gradle"))
	assert.False(t, isBuildFile("pom.xml"))
	assert.False(t, isBuildFile("requirements.txt"))
	assert.False(t, isBuildFile(""))
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

// ── resolveProjectDir ─────────────────────────────────────────────────────────

func TestResolveProjectDir(t *testing.T) {
	p := Plugin{}

	t.Run("returns dir when build.gradle present", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle"), []byte(""), 0o644))

		got, err := p.resolveProjectDir(dir, &ecosystems.SCAPluginOptions{})
		require.NoError(t, err)
		assert.Equal(t, dir, got)
	})

	t.Run("returns dir when build.gradle.kts present", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(""), 0o644))

		got, err := p.resolveProjectDir(dir, &ecosystems.SCAPluginOptions{})
		require.NoError(t, err)
		assert.Equal(t, dir, got)
	})

	t.Run("returns empty string when no Gradle build file found", func(t *testing.T) {
		dir := t.TempDir()

		got, err := p.resolveProjectDir(dir, &ecosystems.SCAPluginOptions{})
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("uses target file directory when target file is a build.gradle", func(t *testing.T) {
		dir := t.TempDir()
		subDir := filepath.Join(dir, "app")
		require.NoError(t, os.Mkdir(subDir, 0o755))
		buildFile := filepath.Join(subDir, "build.gradle")
		require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))

		tf := buildFile
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &tf},
		}

		got, err := p.resolveProjectDir(dir, opts)
		require.NoError(t, err)
		assert.Equal(t, subDir, got)
	})

	t.Run("returns empty when target file is not a Gradle build file", func(t *testing.T) {
		dir := t.TempDir()
		tf := "pom.xml"
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &tf},
		}

		got, err := p.resolveProjectDir(dir, opts)
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("returns error when target file does not exist", func(t *testing.T) {
		dir := t.TempDir()
		tf := "build.gradle" // Gradle file name but doesn't exist
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &tf},
		}

		_, err := p.resolveProjectDir(dir, opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
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

	t.Run("returns error when user init script is not readable", func(t *testing.T) {
		dir := t.TempDir()
		userScript := filepath.Join(dir, "unreadable.gradle")
		require.NoError(t, os.WriteFile(userScript, []byte("// custom"), 0o000)) // no read permission

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: userScript},
		}

		_, err := buildExtraArgs(dir, opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script cannot be read")
	})
}
