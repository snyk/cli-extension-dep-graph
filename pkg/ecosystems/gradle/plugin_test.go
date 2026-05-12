//go:build !integration

package gradle

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/metadata"
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

		args := buildExtraArgs(dir, opts)
		assert.Empty(t, args)
	})

	t.Run("adds user init script as --init-script flag when provided", func(t *testing.T) {
		dir := t.TempDir()
		userScript := filepath.Join(dir, "custom.gradle")
		require.NoError(t, os.WriteFile(userScript, []byte("// custom"), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: userScript},
		}

		args := buildExtraArgs(dir, opts)
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

		args := buildExtraArgs(dir, opts)
		assert.Equal(t, []string{"--init-script", userScript}, args)
	})

	t.Run("handles relative user init script path", func(t *testing.T) {
		dir := t.TempDir()
		scriptsDir := filepath.Join(dir, "scripts")
		require.NoError(t, os.MkdirAll(scriptsDir, 0o755))
		validScript := filepath.Join(scriptsDir, "custom.gradle")
		require.NoError(t, os.WriteFile(validScript, []byte("// custom script"), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: "scripts/custom.gradle"}, // relative path
		}

		args := buildExtraArgs(dir, opts)
		// Should resolve to absolute path
		expectedPath := filepath.Join(dir, "scripts/custom.gradle")
		assert.Equal(t, []string{"--init-script", expectedPath}, args)
	})

	t.Run("handles absolute user init script path", func(t *testing.T) {
		dir := t.TempDir()
		validScript := filepath.Join(dir, "valid.gradle")
		require.NoError(t, os.WriteFile(validScript, []byte("// valid script"), 0o644))

		opts := &ecosystems.SCAPluginOptions{
			Gradle: ecosystems.GradleOptions{InitScript: validScript}, // absolute path
		}

		args := buildExtraArgs(dir, opts)
		assert.Equal(t, []string{"--init-script", validScript}, args)
	})
}

// ── Target file filtering behavior demonstration ──────────────────────────────

func TestTargetFileFiltering_MockedOutput(t *testing.T) {
	ctx := context.Background()
	log := logger.Nop()
	p := Plugin{}

	// Simulate the NDJSON that would be returned by Gradle's :snykDependencyGraph task.
	// This represents a multi-project build with root, app, and lib subprojects.
	// Line 1: metadata; lines 2-4: one project per line.
	mockMultiProjectJSON := `{"gradleVersion":"8.0","javaVersion":"17.0.1","generatedAt":"2023-01-01T12:00:00Z","rootProject":{"name":"myproject","group":"com.example","version":"1.0.0","path":"/project"}}
{"name":"myproject","group":"com.example","version":"1.0.0","path":":","gav":"com.example:myproject:1.0.0","buildFile":"/project/build.gradle","configurations":[{"name":"compileClasspath","description":"Compile classpath","root":{"id":"com.example:myproject:1.0.0","dependencies":[]},"allDependencies":[]}]}
{"name":"app","group":"com.example","version":"1.0.0","path":":app","gav":"com.example:app:1.0.0","buildFile":"/project/app/build.gradle","configurations":[{"name":"compileClasspath","description":"Compile classpath","root":{"id":"com.example:app:1.0.0","dependencies":[{"id":"org.slf4j:slf4j-api:1.7.36","dependencies":[]}]},"allDependencies":[{"id":"org.slf4j:slf4j-api:1.7.36"}]}]}
{"name":"lib","group":"com.example","version":"1.0.0","path":":lib","gav":"com.example:lib:1.0.0","buildFile":"/project/lib/build.gradle","configurations":[{"name":"compileClasspath","description":"Compile classpath","root":{"id":"com.example:lib:1.0.0","dependencies":[{"id":"com.google.guava:guava:31.1-jre","dependencies":[]}]},"allDependencies":[{"id":"com.google.guava:guava:31.1-jre"}]}]}`

	t.Run("demonstrates multi-project output gets filtered to single project", func(t *testing.T) {
		// Parse the mock JSON as if it came from Gradle
		parsed, err := parseDependencyGraphJSON(bytes.NewReader([]byte(mockMultiProjectJSON)))
		require.NoError(t, err)

		// Without target file - should get all 3 projects
		optsAll := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{},
		}

		allResults, allFiles := p.convertProjects(ctx, log, parsed, "/project", "", optsAll)
		assert.Len(t, allResults, 3, "Without target file, should return all projects")
		assert.Len(t, allFiles, 3)

		// Validate ResolverMetadata for all results
		for i, result := range allResults {
			assert.NotNil(t, result.ResolverMetadata, "allResults[%d] ResolverMetadata should not be nil", i)
			assert.Equal(t, "gradle", result.ResolverMetadata.PluginName, "allResults[%d] PluginName should be 'gradle'", i)
			assert.Contains(t, result.ResolverMetadata.VersionBuildInfo, metadata.GradleVersion, "allResults[%d] should contain gradleVersion", i)
			assert.Contains(t, result.ResolverMetadata.VersionBuildInfo, metadata.JavaVersion, "allResults[%d] should contain javaVersion", i)
		}

		// Extract project names for verification
		allProjectNames := make([]string, len(allResults))
		for i, result := range allResults {
			if result.DepGraph != nil && result.DepGraph.GetRootPkg() != nil {
				allProjectNames[i] = result.DepGraph.GetRootPkg().Info.Name
			}
		}
		assert.Contains(t, allProjectNames, "com.example:myproject") // root
		assert.Contains(t, allProjectNames, "com.example:app")       // app subproject
		assert.Contains(t, allProjectNames, "com.example:lib")       // lib subproject

		// With target file - should get only the matching project
		targetFile := "app/build.gradle"
		optsTargeted := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &targetFile},
		}

		targetedResults, targetedFiles := p.convertProjects(ctx, log, parsed, "/project", "", optsTargeted)
		assert.Len(t, targetedResults, 1, "With target file, should return only matching project")
		assert.Len(t, targetedFiles, 1)

		// Verify it's the correct project
		result := targetedResults[0]
		assert.NotNil(t, result.DepGraph)
		assert.Equal(t, "com.example:app", result.DepGraph.GetRootPkg().Info.Name)

		// Validate ResolverMetadata
		assert.NotNil(t, result.ResolverMetadata)
		assert.Equal(t, "gradle", result.ResolverMetadata.PluginName)
		assert.Contains(t, result.ResolverMetadata.VersionBuildInfo, metadata.GradleVersion)
		assert.Contains(t, result.ResolverMetadata.VersionBuildInfo, metadata.JavaVersion)

		// Verify it has the expected dependency (slf4j-api from the mock)
		depGraph := result.DepGraph

		// Check that slf4j-api exists somewhere in the dependency graph
		nodeIDs := make(map[string]bool)
		for _, node := range depGraph.Graph.Nodes {
			nodeIDs[node.NodeID] = true
		}

		var hasSlf4j bool
		for nodeID := range nodeIDs {
			if strings.Contains(nodeID, "slf4j-api") {
				hasSlf4j = true
				break
			}
		}
		assert.True(t, hasSlf4j, "dependency graph should contain slf4j-api")

		// Verify target file in result
		assert.Equal(t, &targetFile, result.ProjectDescriptor.Identity.TargetFile)
	})

	t.Run("demonstrates filtering works with absolute paths", func(t *testing.T) {
		parsed, err := parseDependencyGraphJSON(bytes.NewReader([]byte(mockMultiProjectJSON)))
		require.NoError(t, err)

		// Use absolute path for lib project
		targetFile := "/project/lib/build.gradle"
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &targetFile},
		}

		results, files := p.convertProjects(ctx, log, parsed, "/project", "", opts)
		assert.Len(t, results, 1, "Should return only the lib project")
		assert.Len(t, files, 1)

		// Verify it's the lib project with its specific dependency (guava)
		result := results[0]
		assert.NotNil(t, result.DepGraph)
		assert.Equal(t, "com.example:lib", result.DepGraph.GetRootPkg().Info.Name)

		// Validate ResolverMetadata
		assert.NotNil(t, result.ResolverMetadata)
		assert.Equal(t, "gradle", result.ResolverMetadata.PluginName)
		assert.Contains(t, result.ResolverMetadata.VersionBuildInfo, metadata.GradleVersion)
		assert.Contains(t, result.ResolverMetadata.VersionBuildInfo, metadata.JavaVersion)

		// Verify it has the expected dependency (guava from the mock)
		depGraph := result.DepGraph

		// Check that guava exists somewhere in the dependency graph
		nodeIDs := make(map[string]bool)
		for _, node := range depGraph.Graph.Nodes {
			nodeIDs[node.NodeID] = true
		}

		var hasGuava bool
		for nodeID := range nodeIDs {
			if strings.Contains(nodeID, "guava") {
				hasGuava = true
				break
			}
		}
		assert.True(t, hasGuava, "dependency graph should contain guava")

		// Target file should be converted to relative path in result
		expectedRelative := "lib/build.gradle"
		assert.Equal(t, &expectedRelative, result.ProjectDescriptor.Identity.TargetFile)
	})

	t.Run("demonstrates no results when target file doesn't match", func(t *testing.T) {
		parsed, err := parseDependencyGraphJSON(bytes.NewReader([]byte(mockMultiProjectJSON)))
		require.NoError(t, err)

		targetFile := "nonexistent/build.gradle"
		opts := &ecosystems.SCAPluginOptions{
			Global: ecosystems.GlobalOptions{TargetFile: &targetFile},
		}

		results, files := p.convertProjects(ctx, log, parsed, "/project", "", opts)
		assert.Len(t, results, 0, "Should return no results when no project matches")
		assert.Len(t, files, 0)
	})
}
