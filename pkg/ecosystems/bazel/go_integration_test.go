package bazel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/scatest"
)

func assertGoProcessedFiles(t *testing.T, files []string) {
	t.Helper()
	want := []string{goModFilename, goSumFilename}
	require.Len(t, files, len(want), "processedFiles count")
	bases := make([]string, len(files))
	for i, p := range files {
		bases[i] = filepath.Base(p)
	}
	assert.ElementsMatch(t, want, bases, "processedFiles must end with go.mod and go.sum")
}

// Only run when BAZEL_GO_INTEGRATION_TESTS=1 (needs Bazel on PATH).
func shouldSkipGo(t *testing.T) {
	t.Helper()
	if os.Getenv("BAZEL_GO_INTEGRATION_TESTS") != "1" {
		t.Skip("set BAZEL_GO_INTEGRATION_TESTS=1 to run Bazel Go integration tests")
	}
}

func runGoIntegrationSnapshot(t *testing.T, fixtures []string) {
	t.Helper()

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", fixture))
			require.NoError(t, err)

			opts := ecosystems.NewPluginOptions().WithBazelGo(true)
			plugin := Plugin{}
			results, err := scatest.Run(ctx, plugin, logger.Nop(), root, opts)
			require.NoError(t, err)

			// Paths differ by machine; assert filenames only, snapshot
			// dep-graphs only. Bazel attaches the resolver-scope file list
			// (WORKSPACE, MODULE.bazel, etc.) to every emitted result —
			// any one of them carries the full list.
			require.NotEmpty(t, results)
			assertGoProcessedFiles(t, results[0].ProcessedFiles)

			// ProcessedFiles is asserted above; null it out so the
			// JSON snapshot doesn't capture host-specific paths.
			for i := range results {
				results[i].ProcessedFiles = nil
			}
			snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, struct {
				Results []ecosystems.SCAResult `json:"results"`
			}{Results: results})
		})
	}
}

func TestPlugin_BuildDepGraphsFromDir_GoBinary_MatchJSON(t *testing.T) {
	shouldSkipGo(t)
	runGoIntegrationSnapshot(t, []string{
		"rules-go-0.52.0/basic-gazelle",
		"rules-go-0.60.0/basic-gazelle",
	})
}

func TestPlugin_BuildDepGraphsFromDir_VersionReplace_MatchJSON(t *testing.T) {
	shouldSkipGo(t)
	runGoIntegrationSnapshot(t, []string{
		"rules-go-0.52.0/gazelle-version-replace",
		"rules-go-0.60.0/gazelle-version-replace",
	})
}
