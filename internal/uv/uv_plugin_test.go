package uv

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
)

var logger = zerolog.Nop()

const validSBOMJSON = `{
	"metadata": {
		"component": {
			"name": "test-package",
			"version": "1.0.0"
		}
	},
	"components": []
}`

func singleDepGraphResponse(name, version string) string {
	return `{
		"scanResults": [{
			"facts": [{
				"type": "depGraph",
				"data": {
					"schemaVersion": "1.3.0",
					"pkgManager": {"name": "pip"},
					"pkgs": [{"id": "` + name + `@` + version + `", "info": {"name": "` + name + `", "version": "` + version + `"}}],
					"graph": {
						"rootNodeId": "root-node",
						"nodes": [{"nodeId": "root-node", "pkgId": "` + name + `@` + version + `", "deps": []}]
					}
				}
			}]
		}],
		"warnings": []
	}`
}

func multipleDepGraphsResponse() string {
	return `{
		"scanResults": [
			{
				"facts": [{
					"type": "depGraph",
					"data": {
						"schemaVersion": "1.3.0",
						"pkgManager": {"name": "pip"},
						"pkgs": [{"id": "package1@1.0.0", "info": {"name": "package1", "version": "1.0.0"}}],
						"graph": {
							"rootNodeId": "root-node-1",
							"nodes": [{"nodeId": "root-node-1", "pkgId": "package1@1.0.0", "deps": []}]
						}
					}
				}]
			},
			{
				"facts": [{
					"type": "depGraph",
					"data": {
						"schemaVersion": "1.3.0",
						"pkgManager": {"name": "pip"},
						"pkgs": [{"id": "package2@2.0.0", "info": {"name": "package2", "version": "2.0.0"}}],
						"graph": {
							"rootNodeId": "root-node-2",
							"nodes": [{"nodeId": "root-node-2", "pkgId": "package2@2.0.0", "deps": []}]
						}
					}
				}]
			}
		],
		"warnings": []
	}`
}

func createTestDepGraph(name, version string) *depgraph.DepGraph {
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: "pip"},
		&depgraph.PkgInfo{Name: name, Version: version},
	)
	if err != nil {
		panic(err)
	}
	return builder.Build()
}

func setupMockSnykClientMultiResponse(t *testing.T, responses []mocks.MockResponse) *snykclient.SnykClient {
	t.Helper()
	mockSBOMService := mocks.NewMockSBOMServiceMultiResponse(responses)
	t.Cleanup(func() { mockSBOMService.Close() })
	return snykclient.NewSnykClient(mockSBOMService.Client(), mockSBOMService.URL, "test-org")
}

func setupMockSnykClient(t *testing.T, responseBody string) *snykclient.SnykClient {
	t.Helper()
	mockResponse := mocks.NewMockResponse("application/json", []byte(responseBody), http.StatusOK)
	return setupMockSnykClientMultiResponse(t, []mocks.MockResponse{mockResponse})
}

func TestPlugin_BuildFindingsFromDir(t *testing.T) {
	tests := []struct {
		name         string
		files        []string // files to create relative to root
		allProjects  bool
		exclude      []string // directory/file names to exclude
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
			name:        "missing root file with AllProjects false",
			files:       []string{"README.md"},
			allProjects: false,
			expectedErr: "failed to find uv lockfiles",
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

			// Setup mockClient and plugin
			mockClient := &MockClient{}
			// Create mock SBOM service for conversion - need enough responses for all lock files
			expectedCount := len(tt.expectedDirs)
			mockResponses := make([]mocks.MockResponse, expectedCount)
			//nolint:lll // Long JSON string for mock response
			mockResponseBody := `{"scanResults":[{"facts":[{"type":"depGraph","data":{"schemaVersion":"1.3.0","pkgManager":{"name":"pip"},"pkgs":[{"id":"mock-project@1.0.0","info":{"name":"mock-project","version":"1.0.0"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"root-node","pkgId":"mock-project@1.0.0","deps":[]}]}}}]}],"warnings":[]}`
			for i := range expectedCount {
				mockResponses[i] = mocks.NewMockResponse(
					"application/json",
					[]byte(mockResponseBody),
					http.StatusOK,
				)
			}
			snykClient := setupMockSnykClientMultiResponse(t, mockResponses)
			plugin := NewUvPlugin(mockClient, snykClient, "")

			// Execute
			ctx := context.Background()
			options := &scaplugin.Options{AllProjects: tt.allProjects, Exclude: tt.exclude}
			findings, err := plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)

			// Check error
			if tt.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}

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
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
}

func TestPlugin_ShouldNotSkipProcessingWhenUvLockFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{TargetFile: "uv.lock"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
}

func TestPlugin_SkipsProcessingWhenTargetFileIsNotUVFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{TargetFile: "package.json"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_SkipsProcessingWhenTargetFileIsAPyProjectTomlFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &MockClient{}
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{TargetFile: "pyproject.toml"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
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
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{TargetFile: "my-project/uv.lock"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
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
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{TargetFile: "my-project/package.json"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
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
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	options := &scaplugin.Options{TargetFile: "my-project/uv.lock"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to find uv lockfiles")

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_BuildFindingsFromDir_ErrorHandling(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock")

	mockClient := &MockClient{ReturnErr: errors.New("export failed")}
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(mockClient, snykClient, "")

	ctx := context.Background()
	options := &scaplugin.Options{AllProjects: false}
	findings, err := plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Error)
	require.ErrorContains(t, findings[0].Error, "failed to build dependency graph")

	require.Equal(t, "uv.lock", findings[0].LockFile)
	require.Nil(t, findings[0].DepGraph)
}

func TestPlugin_BuildFindingsFromDir_MixedSuccessAndFailure(t *testing.T) {
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
	options := &scaplugin.Options{AllProjects: true}
	// Mock SBOM service: project1 fails at ExportSBOM (before conversion), so only "." and "project2" need conversion responses
	//nolint:lll // Long JSON string for mock response
	mockResponseBody := `{"scanResults":[{"facts":[{"type":"depGraph","data":{"schemaVersion":"1.3.0","pkgManager":{"name":"pip"},"pkgs":[{"id":"mock-project@1.0.0","info":{"name":"mock-project","version":"1.0.0"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"root-node","pkgId":"mock-project@1.0.0","deps":[]}]}}}]}],"warnings":[]}`
	mockResponses := []mocks.MockResponse{
		mocks.NewMockResponse("application/json", []byte(mockResponseBody), http.StatusOK),
		mocks.NewMockResponse("application/json", []byte(mockResponseBody), http.StatusOK),
	}
	snykClient := setupMockSnykClientMultiResponse(t, mockResponses)
	plugin := NewUvPlugin(mockClient, snykClient, "")
	findings, err := plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 3)

	// Count successful vs error findings
	successCount := 0
	errorCount := 0
	var errorFinding *scaplugin.Finding
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
	require.Equal(t, "project1/uv.lock", errorFinding.LockFile)
	require.Nil(t, errorFinding.DepGraph)
}

func TestBuildFindings_Success(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	mockResponseBody := singleDepGraphResponse("test-package", "1.0.0")
	snykClient := setupMockSnykClient(t, mockResponseBody)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotNil(t, findings[0].DepGraph)
	assert.Equal(t, "uv.lock", findings[0].LockFile)
	assert.Equal(t, "pyproject.toml", findings[0].ManifestFile)
	assert.Nil(t, findings[0].Error)
}

func TestBuildFindings_InvalidSBOM(t *testing.T) {
	sbom := Sbom(`{"invalid": "json"}`)
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	assert.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "failed to parse and validate sbom")
}

func TestBuildFindings_MissingRootComponent(t *testing.T) {
	sbomJSON := `{
		"metadata": {},
		"components": []
	}`
	sbom := Sbom(sbomJSON)
	snykClient := setupMockSnykClient(t, `{}`)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	assert.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "failed to parse and validate sbom")
}

func TestBuildFindings_ConversionError(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	mockResponse := mocks.NewMockResponse("application/json", []byte(`{"error": "invalid"}`), http.StatusBadRequest)
	snykClient := setupMockSnykClientMultiResponse(t, []mocks.MockResponse{mockResponse})
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	assert.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "failed to convert sbom to dep-graphs")
}

func TestBuildFindings_MultipleDepGraphs(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	mockResponseBody := multipleDepGraphsResponse()
	snykClient := setupMockSnykClient(t, mockResponseBody)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, "package1", findings[0].DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "package2", findings[1].DepGraph.GetRootPkg().Info.Name)
}

func TestBuildFindings_WorkspacePackage(t *testing.T) {
	sbomJSON := `{
		"metadata": {
			"component": {
				"name": "workspace-root",
				"version": "1.0.0"
			}
		},
		"components": [
			{
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
	mockResponseBody := singleDepGraphResponse("workspace-package", "3.1.0")
	snykClient := setupMockSnykClient(t, mockResponseBody)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, filepath.Join("packages", "my-package", "pyproject.toml"), findings[0].ManifestFile)
	assert.Equal(t, "uv.lock", findings[0].LockFile)
}

func TestBuildFindings_PathConstruction_RootDir(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	mockResponseBody := singleDepGraphResponse("test-package", "1.0.0")
	snykClient := setupMockSnykClient(t, mockResponseBody)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "uv.lock", ".", &logger)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "pyproject.toml", findings[0].ManifestFile)
	assert.Equal(t, "uv.lock", findings[0].LockFile)
}

func TestBuildFindings_PathConstruction_NestedDir(t *testing.T) {
	sbom := Sbom(validSBOMJSON)
	mockResponseBody := singleDepGraphResponse("test-package", "1.0.0")
	snykClient := setupMockSnykClient(t, mockResponseBody)
	plugin := NewUvPlugin(&MockClient{}, snykClient, "")

	findings, err := plugin.buildFindings(context.Background(), sbom, "project1/uv.lock", "project1", &logger)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, filepath.Join("project1", "pyproject.toml"), findings[0].ManifestFile)
	assert.Equal(t, "project1/uv.lock", findings[0].LockFile)
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
