//go:build !integration
// +build !integration

package pipenv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// TestPlugin_DiscoverPipfiles_HonorsExcludePaths locks in that the pipenv plugin reads
// `opts.Global.ExcludePaths` and passes those paths through to the discovery layer's
// exclude filter — same contract as the other discovery plugins.
func TestPlugin_DiscoverPipfiles_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"Pipfile", "a/Pipfile", "b/Pipfile"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o644))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/Pipfile"})

	got, err := Plugin{}.discoverPipfiles(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/Pipfile",
		"discovery must skip the path supplied via opts.Global.ExcludePaths")
	assert.Contains(t, rels, "Pipfile")
	assert.Contains(t, rels, "b/Pipfile")
}
