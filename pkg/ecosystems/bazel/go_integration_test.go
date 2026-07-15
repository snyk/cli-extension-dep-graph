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

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
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
			t.Cleanup(func() { bazelShutdown(t, root) })

			opts := ecosystems.NewPluginOptions().WithBazelGo(true)
			plugin := Plugin{}
			results, err := scatest.Run(ctx, plugin, debugLogger(), root, opts)
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

// TestPlugin_BuildDepGraphsFromDir_ConditionalDepsSelect_MatchJSON exercises
// the conditional-deps-select fixture, whose deps() is a select() over
// linux/darwin branches. --bazel-platforms pins the target platform passed to
// `bazel cquery`, so each subtest resolves a specific branch deterministically
// regardless of the host OS running the test.
func TestPlugin_BuildDepGraphsFromDir_ConditionalDepsSelect_MatchJSON(t *testing.T) {
	shouldSkipGo(t)

	root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", "rules-go-0.60.0", "conditional-deps-select"))
	require.NoError(t, err)

	tests := []struct {
		name      string
		platforms string
	}{
		{name: "linux_x86_64", platforms: "//:linux_x86_64"},
		{name: "darwin_arm64", platforms: "//:darwin_arm64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { bazelShutdown(t, root) })

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			opts := ecosystems.NewPluginOptions().WithBazelGo(true).WithBazelPlatforms(tc.platforms)
			plugin := Plugin{}
			results, err := scatest.Run(ctx, plugin, debugLogger(), root, opts)
			require.NoError(t, err)
			require.NotEmpty(t, results)

			for i := range results {
				results[i].ProcessedFiles = nil
			}
			snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, struct {
				Results []ecosystems.SCAResult `json:"results"`
			}{Results: results})
		})
	}
}

// TestPlugin_BuildDepGraphsFromDir_ConditionalDepsSelectNoDefault reproduces
// the exact production failure. The fixture has two structurally unrelated
// targets: //:app (a plain go_binary, no select() of its own) and
// //broken:dpkg_status_like (a select() over linux_amd64/linux_arm64 with no
// //conditions:default, mirroring rules_distroless' dpkg_status). Neither
// depends on the other.
//
// Before this fix, target discovery ran `bazel cquery`, which must configure
// every target matched by a pattern like //... before it can filter by
// kind() — so //broken:dpkg_status_like's unmatched select failed discovery
// outright on any host satisfying neither branch, even though it has nothing
// to do with //:app. And unlike buildDepGraph's per-target errors (logged
// and skipped, see plugin.go), a findTargets failure propagates all the way
// up through BuildDepGraphsFromDir as a fatal error — matching the client's
// crash log exactly.
//
// Discovery now runs `bazel query` (loading phase only, never resolves
// selects), so this must succeed and resolve //:app's dep-graph on any host,
// with no --bazel-platforms needed — //:app has no select() of its own, so
// there is nothing for the flag to pin here. (--bazel-platforms forcing a
// specific branch for a target's own conditional deps is covered by the
// sibling conditional-deps-select fixture instead.)
func TestPlugin_BuildDepGraphsFromDir_ConditionalDepsSelectNoDefault(t *testing.T) {
	shouldSkipGo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", "rules-go-0.60.0", "conditional-deps-select-no-default"))
	require.NoError(t, err)
	t.Cleanup(func() { bazelShutdown(t, root) })

	opts := ecosystems.NewPluginOptions().WithBazelGo(true)
	plugin := Plugin{}
	results, err := scatest.Run(ctx, plugin, debugLogger(), root, opts)

	// The regression: this must never error, on any host, with no
	// --bazel-platforms needed. Before the discovery fix (cquery -> query),
	// //broken:dpkg_status_like made findTargets itself fail on any host
	// satisfying neither of its select branches, regardless of //:app.
	require.NoError(t, err)
	require.NotEmpty(t, results, "app has no conditional deps of its own, so its graph should always resolve")

	for i := range results {
		results[i].ProcessedFiles = nil
	}
	snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, struct {
		Results []ecosystems.SCAResult `json:"results"`
	}{Results: results})
}
