package snykclient_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/mocks"
	"github.com/snyk/cli-extension-dep-graph/v2/internal/snykclient"
)

func Test_LookupMavenPackage_Success(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data":[{"id":"pkg:maven/com.example/foo@1.2.3"}]}`),
		http.StatusOK,
	)
	server := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/rest/packages", r.URL.Path)
		q := r.URL.Query()
		assert.NotEmpty(t, q.Get("version"), "request must carry a version qualifier")
		assert.Equal(t, "maven", q.Get("package_type"))
		assert.Equal(t, "ABCDEF", q.Get("package_sha1"))
		assert.Equal(t, "com.example", q.Get("package_namespace"))
		assert.Equal(t, "foo", q.Get("package_name"))
		assert.Equal(t, "1.2.3", q.Get("package_version"))
	})

	client := snykclient.NewSnykClient(server.Client(), server.URL, "org1")
	purl, err := client.LookupMavenPackage(context.Background(), snykclient.MavenPackageQuery{
		Sha1:     "ABCDEF",
		GroupID:  "com.example",
		Artifact: "foo",
		Version:  "1.2.3",
	})
	require.NoError(t, err)
	assert.Equal(t, "pkg:maven/com.example/foo@1.2.3", purl)
}

func Test_LookupMavenPackage_404ReturnsEmpty(t *testing.T) {
	// 404 is the canonical "no mapping" response — not an error from the
	// caller's perspective; the natural fallback is to keep original coordinates.
	response := mocks.NewMockResponse("application/vnd.api+json", []byte(`{}`), http.StatusNotFound)
	server := mocks.NewMockSBOMService(response)

	client := snykclient.NewSnykClient(server.Client(), server.URL, "org1")
	purl, err := client.LookupMavenPackage(context.Background(), snykclient.MavenPackageQuery{Sha1: "X"})
	require.NoError(t, err)
	assert.Empty(t, purl)
}

func Test_LookupMavenPackage_EmptyData(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data":[]}`),
		http.StatusOK,
	)
	server := mocks.NewMockSBOMService(response)

	client := snykclient.NewSnykClient(server.Client(), server.URL, "org1")
	purl, err := client.LookupMavenPackage(context.Background(), snykclient.MavenPackageQuery{Sha1: "X"})
	require.NoError(t, err)
	assert.Empty(t, purl)
}

func Test_LookupMavenPackage_Non404ErrorStatusReturnsError(t *testing.T) {
	// Non-404 failure responses (auth failures, rate limits, server errors, etc.)
	// are returned as errors so callers can log them for debugging.
	errorStatuses := []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	}
	for _, status := range errorStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			response := mocks.NewMockResponse("application/vnd.api+json", []byte(`{}`), status)
			server := mocks.NewMockSBOMService(response)

			client := snykclient.NewSnykClient(server.Client(), server.URL, "org1")
			_, err := client.LookupMavenPackage(context.Background(), snykclient.MavenPackageQuery{Sha1: "X"})
			assert.Errorf(t, err, "expected error for HTTP %d", status)
		})
	}
}
