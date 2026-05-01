package conversion

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

const singleDepGraphResponse = `{
	"scanResults": [{
		"facts": [{
			"type": "depGraph",
			"data": {
				"schemaVersion": "1.3.0",
				"pkgManager": {"name": "uv"},
				"pkgs": [{"id": "test-package@1.0.0", "info": {"name": "test-package", "version": "1.0.0"}}],
				"graph": {
					"rootNodeId": "root-node",
					"nodes": [{"nodeId": "root-node", "pkgId": "test-package@1.0.0", "deps": []}]
				}
			}
		}]
	}],
	"warnings": []
}`

const responseWithWarnings = `{
	"scanResults": [{
		"facts": [{
			"type": "depGraph",
			"data": {
				"schemaVersion": "1.3.0",
				"pkgManager": {"name": "uv"},
				"pkgs": [{"id": "test-package@1.0.0", "info": {"name": "test-package", "version": "1.0.0"}}],
				"graph": {
					"rootNodeId": "root-node",
					"nodes": [{"nodeId": "root-node", "pkgId": "test-package@1.0.0", "deps": []}]
				}
			}
		}]
	}],
	"warnings": [
		{"type": "UnsupportedComponent", "bom_ref": "ref-1", "msg": "first warning"},
		{"type": "MissingPurl", "bom_ref": "ref-2", "msg": "second warning"}
	]
}`

func TestRemoteSBOMConverter_ConvertSBOM_Success(t *testing.T) {
	mockService, snykClient := setupMockSnykClient(t, singleDepGraphResponse, http.StatusOK, nil)
	defer mockService.Close()

	converter := NewRemoteSBOMConverter(snykClient, logger.Nop())
	depGraphs, warnings, err := converter.ConvertSBOM(
		context.Background(),
		bytes.NewReader([]byte(`{"test": "sbom"}`)),
		ConvertSBOMOptions{},
	)

	require.NoError(t, err)
	require.Len(t, depGraphs, 1)
	assert.Equal(t, "test-package", depGraphs[0].GetRootPkg().Info.Name)
	assert.Empty(t, warnings)
}

func TestRemoteSBOMConverter_ConvertSBOM_TranslatesWarnings(t *testing.T) {
	mockService, snykClient := setupMockSnykClient(t, responseWithWarnings, http.StatusOK, nil)
	defer mockService.Close()

	converter := NewRemoteSBOMConverter(snykClient, logger.Nop())
	_, warnings, err := converter.ConvertSBOM(
		context.Background(),
		bytes.NewReader([]byte(`{"test": "sbom"}`)),
		ConvertSBOMOptions{},
	)

	require.NoError(t, err)
	require.Len(t, warnings, 2)
	assert.Equal(t, Warning{Type: "UnsupportedComponent", BOMRef: "ref-1", Msg: "first warning"}, warnings[0])
	assert.Equal(t, Warning{Type: "MissingPurl", BOMRef: "ref-2", Msg: "second warning"}, warnings[1])
}

func TestRemoteSBOMConverter_ConvertSBOM_ForwardsRemoteRepoURL(t *testing.T) {
	var capturedQuery string
	mockService, snykClient := setupMockSnykClient(t, singleDepGraphResponse, http.StatusOK, func(r *http.Request) {
		capturedQuery = r.URL.RawQuery
	})
	defer mockService.Close()

	converter := NewRemoteSBOMConverter(snykClient, logger.Nop())
	_, _, err := converter.ConvertSBOM(
		context.Background(),
		bytes.NewReader([]byte(`{"test": "sbom"}`)),
		ConvertSBOMOptions{RemoteRepoURL: "https://example.com/repo"},
	)

	require.NoError(t, err)
	assert.Contains(t, capturedQuery, "remote_repo_url=https%3A%2F%2Fexample.com%2Frepo")
}

func TestRemoteSBOMConverter_ConvertSBOM_ForwardsForceSingleGraph(t *testing.T) {
	tests := []struct {
		name             string
		forceSingleGraph bool
		wantInQuery      bool
	}{
		{name: "true is forwarded", forceSingleGraph: true, wantInQuery: true},
		{name: "false is omitted", forceSingleGraph: false, wantInQuery: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			mockService, snykClient := setupMockSnykClient(t, singleDepGraphResponse, http.StatusOK, func(r *http.Request) {
				capturedQuery = r.URL.RawQuery
			})
			defer mockService.Close()

			converter := NewRemoteSBOMConverter(snykClient, logger.Nop())
			_, _, err := converter.ConvertSBOM(
				context.Background(),
				bytes.NewReader([]byte(`{"test": "sbom"}`)),
				ConvertSBOMOptions{ForceSingleGraph: tt.forceSingleGraph},
			)

			require.NoError(t, err)
			if tt.wantInQuery {
				assert.Contains(t, capturedQuery, "force_single_graph=true")
			} else {
				assert.NotContains(t, capturedQuery, "force_single_graph")
			}
		})
	}
}

func TestRemoteSBOMConverter_ConvertSBOM_PropagatesError(t *testing.T) {
	mockService, snykClient := setupMockSnykClient(t, `{"error": "bad request"}`, http.StatusBadRequest, nil)
	defer mockService.Close()

	converter := NewRemoteSBOMConverter(snykClient, logger.Nop())
	depGraphs, warnings, err := converter.ConvertSBOM(
		context.Background(),
		bytes.NewReader([]byte(`{"test": "sbom"}`)),
		ConvertSBOMOptions{},
	)

	require.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Nil(t, warnings)
	assert.Contains(t, err.Error(), "failed to convert SBOM")
}

func TestRemoteSBOMConverter_ConvertSBOM_EmptyResultsReturnsEmptySlice(t *testing.T) {
	mockService, snykClient := setupMockSnykClient(t, `{"scanResults": [], "warnings": []}`, http.StatusOK, nil)
	defer mockService.Close()

	converter := NewRemoteSBOMConverter(snykClient, logger.Nop())
	depGraphs, warnings, err := converter.ConvertSBOM(
		context.Background(),
		bytes.NewReader([]byte(`{"test": "sbom"}`)),
		ConvertSBOMOptions{},
	)

	require.NoError(t, err)
	assert.Empty(t, depGraphs)
	assert.Empty(t, warnings)
}

func setupMockSnykClient(
	t *testing.T,
	responseBody string,
	statusCode int,
	assertion func(*http.Request),
) (*httptest.Server, *snykclient.SnykClient) {
	t.Helper()
	resp := mocks.NewMockResponse("application/json", []byte(responseBody), statusCode)
	var assertions []func(*http.Request)
	if assertion != nil {
		assertions = append(assertions, assertion)
	}
	server := mocks.NewMockSBOMService(resp, assertions...)
	client := snykclient.NewSnykClient(server.Client(), server.URL, "test-org")
	return server, client
}
