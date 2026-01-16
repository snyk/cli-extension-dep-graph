package snykclient_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
)

func TestNewSnykClient(t *testing.T) {
	client := snykclient.NewSnykClient(http.DefaultClient, "http://example.com", "org1")
	assert.NotNil(t, client)
}
