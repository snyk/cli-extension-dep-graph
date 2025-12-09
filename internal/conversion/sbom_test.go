package conversion

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSbomToDepGraphs_Success(t *testing.T) {
	logger := zerolog.Nop()
	sbom := bytes.NewReader([]byte(`{"test": "sbom"}`))
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "test-package",
		Version:        "1.0.0",
	}
	mockResponseBody := singleDepGraphMockResponse("test-package", "1.0.0")

	mockService, snykClient := setupMockSnykClient(t, mockResponseBody, http.StatusOK)
	defer mockService.Close()

	depGraphs, err := SbomToDepGraphs(context.Background(), sbom, metadata, snykClient, &logger, "")

	require.NoError(t, err)
	require.Len(t, depGraphs, 1)
	assert.NotNil(t, depGraphs[0])
	rootPkg := depGraphs[0].GetRootPkg()
	assert.Equal(t, "test-package", rootPkg.Info.Name)
	assert.Equal(t, "1.0.0", rootPkg.Info.Version)
}

func TestSbomToDepGraphs_EmptyScans_CreatesEmptyDepGraph(t *testing.T) {
	logger := zerolog.Nop()
	sbom := bytes.NewReader([]byte(`{"test": "sbom"}`))
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "test-package",
		Version:        "3.1.9",
	}
	mockResponseBody := `{"scanResults": [], "warnings": []}`

	mockService, snykClient := setupMockSnykClient(t, mockResponseBody, http.StatusOK)
	defer mockService.Close()

	depGraphs, err := SbomToDepGraphs(context.Background(), sbom, metadata, snykClient, &logger, "")

	require.NoError(t, err)
	require.Len(t, depGraphs, 1)
	assert.NotNil(t, depGraphs[0])
	rootPkg := depGraphs[0].GetRootPkg()
	assert.Equal(t, "test-package", rootPkg.Info.Name)
	assert.Equal(t, "3.1.9", rootPkg.Info.Version)
}

func TestSbomToDepGraphs_MultipleDepGraphs(t *testing.T) {
	logger := zerolog.Nop()
	sbom := bytes.NewReader([]byte(`{"test": "sbom"}`))
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "test-package",
		Version:        "1.0.0",
	}
	mockResponseBody := multipleDepGraphsMockResponse()

	mockService, snykClient := setupMockSnykClient(t, mockResponseBody, http.StatusOK)
	defer mockService.Close()

	depGraphs, err := SbomToDepGraphs(context.Background(), sbom, metadata, snykClient, &logger, "")

	require.NoError(t, err)
	require.Len(t, depGraphs, 2)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
	assert.Equal(t, "package2", depGraphs[1].GetRootPkg().Info.Name)
}

func TestSbomToDepGraphs_ConversionError(t *testing.T) {
	logger := zerolog.Nop()
	sbom := bytes.NewReader([]byte(`{"test": "sbom"}`))
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "test-package",
		Version:        "1.0.0",
	}

	mockService, snykClient := setupMockSnykClient(t, `{"error": "invalid"}`, http.StatusBadRequest)
	defer mockService.Close()

	depGraphs, err := SbomToDepGraphs(context.Background(), sbom, metadata, snykClient, &logger, "")

	assert.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Contains(t, err.Error(), "failed to convert SBOM")
}

func TestSbomToDepGraphs_EmptyDepGraphCreationError_EmptyName(t *testing.T) {
	logger := zerolog.Nop()
	sbom := bytes.NewReader([]byte(`{"test": "sbom"}`))
	metadata := &scaplugin.Metadata{
		PackageManager: "uv",
		Name:           "",
		Version:        "1.0.0",
	}
	mockResponseBody := `{"scanResults": [], "warnings": []}`

	mockService, snykClient := setupMockSnykClient(t, mockResponseBody, http.StatusOK)
	defer mockService.Close()

	depGraphs, err := SbomToDepGraphs(context.Background(), sbom, metadata, snykClient, &logger, "")

	assert.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Contains(t, err.Error(), "found empty Name on metadata")
}

func TestEmptyDepGraph_Success(t *testing.T) {
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "test-package",
		Version:        "1.0.0",
	}

	depGraph, err := emptyDepGraph(metadata)

	require.NoError(t, err)
	assert.NotNil(t, depGraph)
	rootPkg := depGraph.GetRootPkg()
	assert.Equal(t, "test-package", rootPkg.Info.Name)
	assert.Equal(t, "1.0.0", rootPkg.Info.Version)
}

func TestEmptyDepGraph_EmptyPackageManager(t *testing.T) {
	metadata := &scaplugin.Metadata{
		PackageManager: "",
		Name:           "test-package",
		Version:        "3.1.9",
	}

	depGraph, err := emptyDepGraph(metadata)

	assert.Error(t, err)
	assert.Nil(t, depGraph)
	assert.Contains(t, err.Error(), "empty PackageManager")
}

func TestEmptyDepGraph_EmptyName(t *testing.T) {
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "",
		Version:        "1.0.0",
	}

	depGraph, err := emptyDepGraph(metadata)

	assert.Error(t, err)
	assert.Nil(t, depGraph)
	assert.Contains(t, err.Error(), "empty Name")
}

func TestEmptyDepGraph_EmptyVersion(t *testing.T) {
	metadata := &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           "test-package",
		Version:        "",
	}

	depGraph, err := emptyDepGraph(metadata)

	require.NoError(t, err)
	assert.NotNil(t, depGraph)
	rootPkg := depGraph.GetRootPkg()
	assert.Equal(t, "test-package", rootPkg.Info.Name)
	assert.Equal(t, "", rootPkg.Info.Version)
}

func TestExtractDepGraphsFromScans_Success(t *testing.T) {
	depGraph1 := createTestDepGraph("package1", "1.0.0")
	depGraph2 := createTestDepGraph("package2", "2.0.0")

	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: depGraph1},
			},
		},
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: depGraph2},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	require.Len(t, depGraphs, 2)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
	assert.Equal(t, "package2", depGraphs[1].GetRootPkg().Info.Name)
}

func TestExtractDepGraphsFromScans_MultipleFactsInSingleScan(t *testing.T) {
	depGraph1 := createTestDepGraph("package1", "1.0.0")
	depGraph2 := createTestDepGraph("package2", "2.0.0")

	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: depGraph1},
				{Type: "depGraph", Data: depGraph2},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	require.Len(t, depGraphs, 2)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
	assert.Equal(t, "package2", depGraphs[1].GetRootPkg().Info.Name)
}

func TestExtractDepGraphsFromScans_WrongFactType(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "otherType", Data: "some data"},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0) // Wrong fact types are skipped
}

func TestExtractDepGraphsFromScans_MixedFactTypes(t *testing.T) {
	depGraph1 := createTestDepGraph("package1", "1.0.0")

	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "otherType", Data: "some data"},
				{Type: "depGraph", Data: depGraph1},
				{Type: "anotherType", Data: 123},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	require.Len(t, depGraphs, 1)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
}

func TestExtractDepGraphsFromScans_TypeAssertionFailure(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: "not a depGraph"}, // Wrong type
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	assert.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Contains(t, err.Error(), "expected fact.Data to be *depgraph.DepGraph")
}

func TestExtractDepGraphsFromScans_NilDepGraph(t *testing.T) {
	var nilDepGraph *depgraph.DepGraph
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: nilDepGraph},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	assert.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Contains(t, err.Error(), "depGraph is nil")
}

func TestExtractDepGraphsFromScans_NoDepGraphFacts(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "fact1", Data: "data1"},
				{Type: "fact2", Data: "data2"},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func TestExtractDepGraphsFromScans_EmptyScans(t *testing.T) {
	scans := []*snykclient.ScanResult{}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func TestExtractDepGraphsFromScans_NilScans(t *testing.T) {
	var scans []*snykclient.ScanResult

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func TestExtractDepGraphsFromScans_ScanWithNoFacts(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func singleDepGraphMockResponse(name, version string) string {
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

func multipleDepGraphsMockResponse() string {
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

func setupMockSnykClient(t *testing.T, responseBody string, statusCode int) (*httptest.Server, *snykclient.SnykClient) {
	t.Helper()
	mockService := mocks.NewMockSBOMService(
		mocks.NewMockResponse("application/json", []byte(responseBody), statusCode),
	)
	snykClient := snykclient.NewSnykClient(mockService.Client(), mockService.URL, "test-org")
	return mockService, snykClient
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
