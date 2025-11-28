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

	// Add some dot folders
	filesToSetup[".git/requirements.txt"] = "test content"
	filesToSetup[".venv/requirements.txt"] = "test content"
	filesToSetup[".env/requirements.txt"] = "test content"
	filesToSetup[".tox/requirements.txt"] = "test content"
	filesToSetup[".pytest_cache/requirements.txt"] = "test content"
	filesToSetup[".mypy_cache/requirements.txt"] = "test content"
	filesToSetup[".ruff_cache/requirements.txt"] = "test content"
	filesToSetup[".eggs/requirements.txt"] = "test content"

	setupFiles(t, tmpDir, filesToSetup)

	results, err := FindFiles(context.Background(), tmpDir,
		WithInclude("requirements.txt"),
		WithCommonExcludes())

	require.NoError(t, err)
	assert.Empty(t, results, "WithCommonExcludes should filter out all files in excluded folders")
}
