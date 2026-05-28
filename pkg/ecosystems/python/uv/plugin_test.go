package uv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/scatest"
)

var testLogger = logger.Nop()

const validSBOMJSON = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.5",
	"version": 1,
	"metadata": {
		"tools": [{"vendor": "Astral Software Inc.", "name": "uv", "version": "0.10.9"}],
		"component": {
			"type": "library",
			"bom-ref": "test-package-1@1.0.0",
			"name": "test-package",
			"version": "1.0.0",
			"properties": [
				{"name": "uv:package:is_project_root", "value": "true"}
			]
		}
	},
	"components": []
}`

func createTestDepGraph(name, version string) *depgraph.DepGraph {
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: "uv"},
		&depgraph.PkgInfo{Name: name, Version: version},
	)
	if err != nil {
		panic(err)
	}
	return builder.Build()
}

// mockConverter returns a MockSBOMConverter that returns the given depgraphs
// on every call. If no depgraphs are passed, the plugin's empty-depgraph
// fallback will produce a single depgraph from the SBOM's metadata.
func mockConverter(depGraphs ...*depgraph.DepGraph) *MockSBOMConverter {
	return &MockSBOMConverter{DepGraphs: depGraphs}
}

// erroringConverter returns a MockSBOMConverter that returns the given error
// from ConvertSBOM.
func erroringConverter(err error) *MockSBOMConverter {
	return &MockSBOMConverter{Err: err}
}

func TestPlugin_BuildDepGraphsFromDir(t *testing.T) {
	tests := []struct {
		name         string
		files        []string // files to create relative to root
		allProjects  bool
		exclude      []string // basename/dirname patterns (--exclude semantic)
		excludePaths []string // exact path patterns (--exclude-paths semantic / processed-files channel)
		expectedDirs []string // expected directories (relative paths) that should be processed
		expectedErr  string   // if non-empty, expect error containing this string
	}{
		// Happy path - single file
		{
			name:         "single uv.lock at root",
			files:        []string{"uv.lock"},
			allProjects:  false,
			expectedDirs: []string{"."},
		},

		// AllProjects behavior
		{
			name:         "AllProjects false - only finds root",
			files:        []string{"uv.lock", "nested/uv.lock"},
			allProjects:  false,
			expectedDirs: []string{"."},
		},
		{
			name:         "AllProjects true - finds all nested files",
			files:        []string{"uv.lock", "project1/uv.lock", "project2/uv.lock", "project1/sub/uv.lock"},
			allProjects:  true,
			expectedDirs: []string{".", "project1", "project1/sub", "project2"},
		},

		// Exclusions
		{
			name: "excludes common folders",
			files: []string{
				"uv.lock",
				"src/uv.lock",
				"node_modules/uv.lock",
				".build/uv.lock",
			},
			allProjects:  true,
			expectedDirs: []string{".", "src"}, // only root and src
		},

		// CLI exclude flag
		{
			name: "excludes directories by name with exclude flag",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
				"src/dir1/uv.lock",
				"src/dir2/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"dir1"},
			expectedDirs: []string{".", "src/dir2"},
		},
		{
			name: "excludes multiple directories with exclude flag",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
				"dir2/uv.lock",
				"src/uv.lock",
				"src/dir1/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"dir1", "dir2"},
			expectedDirs: []string{".", "src"},
		},
		{
			name: "exclude flag combined with common excludes",
			files: []string{
				"uv.lock",
				"node_modules/uv.lock",
				"custom-exclude/uv.lock",
				"src/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"custom-exclude"},
			expectedDirs: []string{".", "src"},
		},
		{
			name: "exclude flag has no effect when allProjects is false",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
			},
			allProjects:  false,
			exclude:      []string{"dir1"},
			expectedDirs: []string{"."},
		},

		// CLI exclude-paths flag (also covers cross-plugin processed-files propagation, since
		// orchestrators push processed file paths through this same opts.Global.ExcludePaths channel).
		{
			name: "excludes exact paths via excludePaths",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
				"dir2/uv.lock",
			},
			allProjects:  true,
			excludePaths: []string{"dir1/uv.lock"},
			expectedDirs: []string{".", "dir2"},
		},
		{
			name: "exclude and excludePaths combine",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
				"dir2/uv.lock",
				"dir3/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"dir1"},
			excludePaths: []string{"dir2/uv.lock"},
			expectedDirs: []string{".", "dir3"},
		},

		// Edge cases
		{
			name:         "no files found",
			files:        []string{"README.md", "pyproject.toml"},
			allProjects:  true,
			expectedDirs: []string{}, // empty result, no error
		},
		{
			name:         "empty directory",
			files:        []string{},
			allProjects:  true,
			expectedDirs: []string{},
		},
		{
			name:         "missing root file with AllProjects false",
			files:        []string{"README.md"},
			allProjects:  false,
			expectedDirs: []string{}, // empty result, no error
		},

		// Multiple projects
		{
			name:         "multiple top-level projects",
			files:        []string{"uv.lock", "backend/uv.lock", "frontend/uv.lock"},
			allProjects:  true,
			expectedDirs: []string{".", "backend", "frontend"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := createFiles(t, tt.files...)

			mockClient := &MockClient{}
			plugin := NewPlugin(mockClient, mockConverter(createTestDepGraph("mock-project", "1.0.0")), "")

			// Execute
			ctx := context.Background()
			options := ecosystems.NewPluginOptions().
				WithAllProjects(tt.allProjects).
				WithExclude(tt.exclude).
				WithExcludePaths(tt.excludePaths)
			results, err := scatest.Run(ctx, plugin, testLogger, tmpDir, options)

			// Check error
			if tt.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}

			findings := results

			// Verify correct directories were processed
			gotDirs := mockClient.CalledDirs
			expectedDirs := append([]string{}, tt.expectedDirs...)
			sort.Strings(gotDirs)
			sort.Strings(expectedDirs)

			if len(gotDirs) != len(expectedDirs) {
				t.Errorf("Expected %d directories, got %d\n  expected: %v\n  got:  %v",
					len(expectedDirs), len(gotDirs), expectedDirs, gotDirs)
				return
			}

			for i := range expectedDirs {
				if gotDirs[i] != expectedDirs[i] {
					t.Errorf("Directory mismatch at index %d:\n  expected: %v\n  got:  %v",
						i, expectedDirs, gotDirs)
					break
				}
			}

			if len(findings) != len(tt.expectedDirs) {
				t.Errorf("Expected %d findings, got %d", len(tt.expectedDirs), len(findings))
			}
		})
	}
}

func TestPlugin_ShouldNotSkipProcessingWhenNoTargetFileIsSet(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions()
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
}

func TestPlugin_ShouldNotSkipProcessingWhenUvLockFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions().WithTargetFile("uv.lock")
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
}

func TestPlugin_SkipsProcessingWhenTargetFileIsNotUVFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions().WithTargetFile("package.json")
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_SkipsProcessingWhenTargetFileIsAPyProjectTomlFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions().WithTargetFile("pyproject.toml")
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_ShouldNotSkipProcessingWhenTargetFileIsRelativeFolderPath(t *testing.T) {
	tmpDir := createFiles(t,
		"my-project/uv.lock",
		"my-project/pyproject.toml",
		"other-project/uv.lock",
		"other-project/pyproject.toml",
	)

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions().WithTargetFile("my-project/uv.lock")
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings for the specific uv.lock file")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
	require.Equal(t, "my-project", mockClient.CalledDirs[0], "Should have called uv client with the correct directory")
}

func TestPlugin_ShouldSkipProcessingWhenTargetFileIsNotUvLockInRelativeFolderPath(t *testing.T) {
	tmpDir := createFiles(t,
		"my-project/package.json",
		"my-project/package-lock.json",
		"other-project/uv.lock",
		"other-project/pyproject.toml",
	)

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions().WithTargetFile("my-project/package.json")
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_ShouldRaiseErrorWhenTargetFileIsUvLockInRelativeFolderButDoesNotExist(t *testing.T) {
	tmpDir := createFiles(t,
		"my-project/package.json",
		"my-project/package-lock.json",
		"other-project/uv.lock",
		"other-project/pyproject.toml",
	)

	mockClient := &MockClient{}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	options := ecosystems.NewPluginOptions().WithTargetFile("my-project/uv.lock")
	results, err := scatest.Run(t.Context(), plugin, testLogger, tmpDir, options)

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to find uv lockfile(s)")

	require.Empty(t, results, "Should emit no results on error")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_BuildDepGraphsFromDir_ErrorHandling(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock")

	mockClient := &MockClient{ReturnErr: errors.New("export failed")}
	plugin := NewPlugin(mockClient, mockConverter(), "")

	ctx := context.Background()
	options := ecosystems.NewPluginOptions()
	results, err := scatest.Run(ctx, plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Error)
	require.ErrorContains(t, findings[0].Error, "failed to build dependency graph")

	require.Equal(t, "uv.lock", findings[0].ResolverMetadata.NormalisedTargetFile)
	require.Nil(t, findings[0].DepGraph)
}

func TestPlugin_BuildDepGraphsFromDir_MixedSuccessAndFailure(t *testing.T) {
	// Create multiple lock files
	tmpDir := createFiles(t,
		"uv.lock",
		"project1/uv.lock",
		"project2/uv.lock",
	)

	// Setup mock to fail for project1 but succeed for others
	mockClient := &MockClient{
		ErrorDirs: map[string]error{
			"project1": errors.New("uv export failed"),
		},
	}
	ctx := context.Background()
	options := ecosystems.NewPluginOptions().WithAllProjects(true)
	// project1 fails at ExportSBOM (before conversion), so the converter is only called for "." and "project2".
	plugin := NewPlugin(mockClient, mockConverter(createTestDepGraph("mock-project", "1.0.0")), "")
	results, err := scatest.Run(ctx, plugin, testLogger, tmpDir, options)
	findings := results
	require.NoError(t, err)

	require.Len(t, findings, 3)

	// Count successful vs error findings
	successCount := 0
	errorCount := 0
	var errorFinding *ecosystems.SCAResult
	for i := range findings {
		if findings[i].Error != nil {
			errorCount++
			errorFinding = &findings[i]
		} else {
			successCount++
		}
	}
	require.Equal(t, 2, successCount, "Expected 2 successful findings")
	require.Equal(t, 1, errorCount, "Expected 1 error finding")

	require.NotNil(t, errorFinding)
	require.ErrorContains(t, errorFinding.Error, "failed to build dependency graph")
	require.Equal(t, "project1/uv.lock", errorFinding.ResolverMetadata.NormalisedTargetFile)
	require.Nil(t, errorFinding.DepGraph)
}

func TestBuildFindings_Success(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("test-package", "1.0.0")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotNil(t, findings[0].DepGraph)
	assert.Equal(t, "pyproject.toml", findings[0].ResolverMetadata.NormalisedTargetFile)
	assert.Nil(t, findings[0].Error)
	assert.Equal(t, []string{"uv.lock", "pyproject.toml", "requirements.txt"}, findings[0].ProcessedFiles)
}

func TestBuildFindings_NoProjectRoot_ReturnsErrorFinding(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"tools": [{"vendor": "Astral Software Inc.", "name": "uv", "version": "0.10.9"}],
			"component": {
				"type": "library",
				"bom-ref": "uv-workspace-3",
				"name": "uv-workspace",
				"properties": [
					{"name": "uv:package:is_synthetic_root", "value": "true"}
				]
			}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "albatross-1@0.1.0",
				"name": "albatross",
				"version": "0.1.0",
				"properties": [
					{"name": "uv:workspace:path", "value": "packages/albatross"}
				]
			},
			{
				"type": "library",
				"bom-ref": "seeds-2@1.0.0",
				"name": "seeds",
				"version": "1.0.0",
				"properties": [
					{"name": "uv:workspace:path", "value": "packages/seeds"}
				]
			}
		]
	}`
	sbom := Sbom(sbomJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)
	findings := results

	require.NoError(t, err, "should not return an error, but rather an error finding")
	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Error)
	assert.Contains(t, findings[0].Error.Error(), "No root project found")
	assert.Nil(t, findings[0].DepGraph)
	assert.Equal(t, "uv.lock", findings[0].ResolverMetadata.NormalisedTargetFile)

	var catalogErr snyk_errors.Error
	require.True(t, errors.As(findings[0].Error, &catalogErr), "error should be a catalog error")
	assert.Equal(t, "SNYK-OS-UV-0001", catalogErr.ErrorCode)
	assert.Contains(t, catalogErr.Detail, "no root")
	assert.Contains(t, catalogErr.Detail, "--all-projects")
}

func TestBuildFindings_NoProjectRoot_AllProjects_Succeeds(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"tools": [{"vendor": "Astral Software Inc.", "name": "uv", "version": "0.10.9"}],
			"component": {
				"type": "library",
				"bom-ref": "uv-workspace-3",
				"name": "uv-workspace",
				"properties": [
					{"name": "uv:package:is_synthetic_root", "value": "true"}
				]
			}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "albatross-1@0.1.0",
				"name": "albatross",
				"version": "0.1.0",
				"properties": [
					{"name": "uv:workspace:path", "value": "packages/albatross"}
				]
			}
		]
	}`
	sbom := Sbom(sbomJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("albatross", "0.1.0")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions().WithAllProjects(true), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotNil(t, findings[0].DepGraph)
	assert.Nil(t, findings[0].Error)
}

func TestBuildFindings_NoProjectRoot_UvWorkspacePackages_Succeeds(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"tools": [{"vendor": "Astral Software Inc.", "name": "uv", "version": "0.10.9"}],
			"component": {
				"type": "library",
				"bom-ref": "uv-workspace-3",
				"name": "uv-workspace",
				"properties": [
					{"name": "uv:package:is_synthetic_root", "value": "true"}
				]
			}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "albatross-1@0.1.0",
				"name": "albatross",
				"version": "0.1.0",
				"properties": [
					{"name": "uv:workspace:path", "value": "packages/albatross"}
				]
			}
		]
	}`
	sbom := Sbom(sbomJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("albatross", "0.1.0")), "")

	results, err := collectBuildResults(
		context.Background(),
		plugin,
		sbom,
		"uv.lock",
		".",
		ecosystems.NewPluginOptions().WithForceIncludeWorkspacePackages(true),
		testLogger,
	)
	findings := results

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotNil(t, findings[0].DepGraph)
	assert.Nil(t, findings[0].Error)
	assert.Equal(t, filepath.Join("packages", "albatross", "pyproject.toml"), findings[0].ResolverMetadata.NormalisedTargetFile)
}

func TestBuildFindings_InvalidSBOM(t *testing.T) {
	sbom := Sbom(`{"invalid": "json"}`)
	plugin := NewPlugin(&MockClient{}, mockConverter(), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	assert.Error(t, err)
	assert.Empty(t, results)
	assert.Contains(t, err.Error(), "failed to parse and validate sbom")
}

func TestBuildFindings_MissingRootComponent(t *testing.T) {
	sbomJSON := `{
		"metadata": {},
		"components": []
	}`
	sbom := Sbom(sbomJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	assert.Error(t, err)
	assert.Empty(t, results)
	assert.Contains(t, err.Error(), "failed to parse and validate sbom")
}

func TestBuildFindings_ConversionError(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	plugin := NewPlugin(&MockClient{}, erroringConverter(errors.New("api request failed")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	assert.Error(t, err)
	assert.Empty(t, results)
	assert.Contains(t, err.Error(), "failed to convert sbom to dep-graphs")
}

func TestBuildFindings_EmptyDepGraphFallback_BuildsFromMetadata(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	// Converter returns no depgraphs (e.g. workspace with no deps).
	// The plugin should fall back to building an empty depgraph from the SBOM root metadata.
	plugin := NewPlugin(&MockClient{}, mockConverter(), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	require.NoError(t, err)
	require.Len(t, results, 1)
	finding := results[0]
	require.NotNil(t, finding.DepGraph)
	rootPkg := finding.DepGraph.GetRootPkg()
	assert.Equal(t, "test-package", rootPkg.Info.Name)
	assert.Equal(t, "1.0.0", rootPkg.Info.Version)
	assert.Equal(t, "uv", finding.DepGraph.PkgManager.Name)
}

func TestBuildFindings_ForwardsForceSingleGraphToConverter(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	converter := mockConverter(createTestDepGraph("test-package", "1.0.0"))
	plugin := NewPlugin(&MockClient{}, converter, "")

	_, err := collectBuildResults(
		context.Background(),
		plugin,
		sbom,
		"uv.lock",
		".",
		ecosystems.NewPluginOptions().WithForceSingleGraph(true),
		testLogger,
	)

	require.NoError(t, err)
	require.Len(t, converter.CalledOptions, 1)
	assert.True(t, converter.CalledOptions[0].ForceSingleGraph)
}

func TestBuildFindings_ForwardsRemoteRepoURLToConverter(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	converter := mockConverter(createTestDepGraph("test-package", "1.0.0"))
	plugin := NewPlugin(&MockClient{}, converter, "https://example.com/repo")

	_, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	require.NoError(t, err)
	require.Len(t, converter.CalledOptions, 1)
	assert.Equal(t, "https://example.com/repo", converter.CalledOptions[0].RemoteRepoURL)
}

func TestBuildFindings_MultipleDepGraphs(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(
		createTestDepGraph("package1", "1.0.0"),
		createTestDepGraph("package2", "2.0.0"),
	), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, "package1", findings[0].DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "package2", findings[1].DepGraph.GetRootPkg().Info.Name)
}

func TestBuildFindings_WorkspacePackage(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"tools": [{"vendor": "Astral Software Inc.", "name": "uv", "version": "0.10.9"}],
			"component": {
				"type": "library",
				"bom-ref": "workspace-root-1@1.0.0",
				"name": "workspace-root",
				"version": "1.0.0",
				"properties": [
					{"name": "uv:package:is_project_root", "value": "true"}
				]
			}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "workspace-package-2@3.1.0",
				"name": "workspace-package",
				"version": "3.1.0",
				"properties": [
					{
						"name": "uv:workspace:path",
						"value": "packages/my-package"
					}
				]
			}
		]
	}`
	sbom := Sbom(sbomJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("workspace-package", "3.1.0")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, filepath.Join("packages", "my-package", "pyproject.toml"), findings[0].ResolverMetadata.NormalisedTargetFile)
}

func TestBuildFindings_PathConstruction_RootDir(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("test-package", "1.0.0")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "uv.lock", ".", ecosystems.NewPluginOptions(), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "pyproject.toml", findings[0].ResolverMetadata.NormalisedTargetFile)
}

func TestBuildFindings_PathConstruction_NestedDir(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("test-package", "1.0.0")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "project1/uv.lock", "project1", ecosystems.NewPluginOptions(), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, filepath.Join("project1", "pyproject.toml"), findings[0].ResolverMetadata.NormalisedTargetFile)
}

func TestBuildFindings_PathConstruction_NestedWorkspacePackage(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"tools": [{"vendor": "Astral Software Inc.", "name": "uv", "version": "0.10.9"}],
			"component": {
				"type": "library",
				"bom-ref": "workspace-root-1@1.0.0",
				"name": "workspace-root",
				"version": "1.0.0",
				"properties": [
					{"name": "uv:package:is_project_root", "value": "true"}
				]
			}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "workspace-package-2@3.1.0",
				"name": "workspace-package",
				"version": "3.1.0",
				"properties": [
					{
						"name": "uv:workspace:path",
						"value": "packages/my-package"
					}
				]
			}
		]
	}`
	sbom := Sbom(sbomJSON)
	plugin := NewPlugin(&MockClient{}, mockConverter(createTestDepGraph("workspace-package", "3.1.0")), "")

	results, err := collectBuildResults(context.Background(), plugin, sbom, "workspace/uv.lock", "workspace", ecosystems.NewPluginOptions(), testLogger)

	findings := results
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, filepath.Join("workspace", "packages", "my-package", "pyproject.toml"), findings[0].ResolverMetadata.NormalisedTargetFile)
}

func TestFindWorkspacePackage_MatchFound(t *testing.T) {
	depGraph := createTestDepGraph("workspace-package", "3.1.9")
	workspacePackages := []WorkspacePackage{
		{Name: "other-package", Version: "1.0.0", Path: "other"},
		{Name: "workspace-package", Version: "3.1.9", Path: "packages/my-package"},
		{Name: "another-package", Version: "2.0.0", Path: "another"},
	}

	result := findWorkspacePackage(depGraph, workspacePackages)

	require.NotNil(t, result)
	assert.Equal(t, "workspace-package", result.Name)
	assert.Equal(t, "packages/my-package", result.Path)
}

func TestFindWorkspacePackage_NoMatch(t *testing.T) {
	depGraph := createTestDepGraph("not-in-workspace", "1.0.0")
	workspacePackages := []WorkspacePackage{
		{Name: "package1", Version: "1.0.0", Path: "pkg1"},
		{Name: "package2", Version: "2.0.0", Path: "pkg2"},
	}

	result := findWorkspacePackage(depGraph, workspacePackages)

	assert.Nil(t, result)
}

func TestFindWorkspacePackage_EmptyWorkspacePackages(t *testing.T) {
	depGraph := createTestDepGraph("test-package", "1.0.0")
	workspacePackages := []WorkspacePackage{}

	result := findWorkspacePackage(depGraph, workspacePackages)

	assert.Nil(t, result)
}

func TestBuildEmptyDepGraph(t *testing.T) {
	tests := []struct {
		name        string
		metadata    *sbomMetadata
		wantErr     string
		wantName    string
		wantVersion string
	}{
		{
			name:        "all fields set",
			metadata:    &sbomMetadata{PackageManager: "pip", Name: "test-package", Version: "1.0.0"},
			wantName:    "test-package",
			wantVersion: "1.0.0",
		},
		{
			name:        "empty version is allowed",
			metadata:    &sbomMetadata{PackageManager: "pip", Name: "test-package", Version: ""},
			wantName:    "test-package",
			wantVersion: "",
		},
		{
			name:     "empty PackageManager errors",
			metadata: &sbomMetadata{PackageManager: "", Name: "test-package", Version: "1.0.0"},
			wantErr:  "empty PackageManager",
		},
		{
			name:     "empty Name errors",
			metadata: &sbomMetadata{PackageManager: "pip", Name: "", Version: "1.0.0"},
			wantErr:  "empty Name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			depGraph, err := buildEmptyDepGraph(tt.metadata)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Nil(t, depGraph)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, depGraph)
			rootPkg := depGraph.GetRootPkg()
			assert.Equal(t, tt.wantName, rootPkg.Info.Name)
			assert.Equal(t, tt.wantVersion, rootPkg.Info.Version)
		})
	}
}

func TestPlugin_DiscoverLockFiles(t *testing.T) {
	tests := []struct {
		name string

		files       []string // files to create relative to root
		allProjects bool
		targetFile  string
		exclude     []string

		expectedFiles []string // expected relative paths of discovered files
		expectedErr   string   // if non-empty, expect error containing this string
	}{
		// ========== AllProjects = true ==========
		{
			name:          "AllProjects true - finds all uv.lock files including nested",
			files:         []string{"uv.lock", "project1/uv.lock", "foo/pyproject.toml", "a/b/c/uv.lock"},
			allProjects:   true,
			targetFile:    "",
			expectedFiles: []string{"uv.lock", "project1/uv.lock", "a/b/c/uv.lock"},
		},
		{
			name:          "AllProjects true - no files found",
			files:         []string{"README.md", "pyproject.toml"},
			allProjects:   true,
			targetFile:    "",
			expectedFiles: []string{},
		},
		{
			name:          "AllProjects true - excludes common folders",
			files:         []string{"uv.lock", "src/uv.lock", "node_modules/uv.lock", ".build/uv.lock"},
			allProjects:   true,
			targetFile:    "",
			expectedFiles: []string{"uv.lock", "src/uv.lock"}, // node_modules and .build excluded
		},
		{
			name:          "AllProjects true - ignores excluded directories",
			files:         []string{"uv.lock", "dir1/uv.lock", "dir2/uv.lock", "src/uv.lock"},
			allProjects:   true,
			targetFile:    "",
			exclude:       []string{"dir1", "dir2"},
			expectedFiles: []string{"uv.lock", "src/uv.lock"},
		},

		// ========== AllProjects = false, targetFile = "" ==========
		{
			name:          "AllProjects false, targetFile empty - finds only root uv.lock",
			files:         []string{"uv.lock", "project1/uv.lock", "project2/uv.lock"},
			allProjects:   false,
			targetFile:    "",
			expectedFiles: []string{"uv.lock"},
		},
		{
			name:          "AllProjects false, targetFile empty - no root file returns empty slice",
			files:         []string{"project1/uv.lock"},
			allProjects:   false,
			targetFile:    "",
			expectedFiles: []string{}, // Empty slice, no error
		},

		// ========== AllProjects = false, targetFile != "" ==========
		{
			name:          "AllProjects false, targetFile specified - finds nested file",
			files:         []string{"uv.lock", "project1/uv.lock"},
			allProjects:   false,
			targetFile:    "project1/uv.lock",
			expectedFiles: []string{"project1/uv.lock"},
		},
		{
			name:          "AllProjects false, targetFile specified - deep nested file",
			files:         []string{"uv.lock", "a/b/c/uv.lock"},
			allProjects:   false,
			targetFile:    "a/b/c/uv.lock",
			expectedFiles: []string{"a/b/c/uv.lock"},
		},
		{
			name:        "AllProjects false, targetFile specified - file doesn't exist returns error",
			files:       []string{"uv.lock", "project1/uv.lock"},
			allProjects: false,
			targetFile:  "nonexistent/uv.lock",
			expectedErr: "failed to find uv lockfile(s)",
		},
		{
			name:          "AllProjects false, targetFile specified - ignores other files",
			files:         []string{"uv.lock", "project1/uv.lock", "project2/uv.lock"},
			allProjects:   false,
			targetFile:    "project1/uv.lock",
			expectedFiles: []string{"project1/uv.lock"}, // Only the specified file
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := createFiles(t, tt.files...)
			plugin := NewPlugin(&MockClient{}, nil, "")

			ctx := context.Background()
			options := ecosystems.NewPluginOptions().
				WithAllProjects(tt.allProjects).
				WithExclude(tt.exclude)
			if tt.targetFile != "" {
				options = options.WithTargetFile(tt.targetFile)
			}

			files, err := plugin.discoverLockFiles(ctx, tmpDir, tt.targetFile, options)

			if tt.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, files)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, files)

			// Extract relative paths from results
			relPaths := make([]string, len(files))
			for i, f := range files {
				relPaths[i] = f.RelPath
			}

			// Sort for comparison
			sort.Strings(relPaths)
			sort.Strings(tt.expectedFiles)

			require.Equal(t, tt.expectedFiles, relPaths,
				"Expected files %v, got %v", tt.expectedFiles, relPaths)
		})
	}
}

// Helper to create files.
func createFiles(t *testing.T, files ...string) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "uv-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	for _, file := range files {
		fullPath := filepath.Join(tmpDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte("# test file"), 0o600); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}

	return tmpDir
}
