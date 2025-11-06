package snykclient_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
)

var (
	logger     = zerolog.New(&bytes.Buffer{})
	errFactory = snykclient.NewErrorFactory(&logger)
)

func TestNewSnykClient(t *testing.T) {
	client := snykclient.NewSnykClient(http.DefaultClient, "http://example.com", "org1")
	assert.NotNil(t, client)
}
