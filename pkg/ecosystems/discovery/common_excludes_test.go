//go:build !integration
// +build !integration

package discovery

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommonExcludes(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file in each excluded folder
	filesToSetup := make(map[string]string)
	for _, folder := range commonExcludes {
		if strings.Contains(folder, "*") {
			continue
		}
		// Create a requirements.txt file in each folder
		filesToSetup[folder+"/requirements.txt"] = "test content"
	}

	setupFiles(t, tmpDir, filesToSetup)

	results, err := FindFiles(context.Background(), tmpDir,
		WithInclude("requirements.txt"),
		WithCommonExcludes())

	require.NoError(t, err)
	assert.Empty(t, results, "WithCommonExcludes should filter out all files in excluded folders")
}
