package snykclient_test

import (
	"bytes"
	_ "embed"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
)

//go:embed testdata/sbom-test-result.response.json
var testResultMockResponse []byte

var (
	logger     = zerolog.New(&bytes.Buffer{})
	errFactory = snykclient.NewErrorFactory(&logger)
)

func TestNewSnykClient(t *testing.T) {
	client := snykclient.NewSnykClient(http.DefaultClient, "http://example.com", "org1")
	assert.NotNil(t, client)
}
