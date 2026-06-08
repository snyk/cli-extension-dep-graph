//go:build integration && poetry
// +build integration,poetry

// Integration tests for the poetry plugin. Gated behind the
// `integration` and `poetry` build tags so they only run when the real
// poetry binary is present.
//
// Run with: `make test-poetry-integration`
package poetry

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var updateGolden = flag.Bool("update", false, "overwrite expected.json golden files with current plugin output")

// requirePoetry fails the test immediately if poetry is absent from
// PATH or below the supported minimum version, logging the detected
// version for CI diagnostics.
func requirePoetry(t *testing.T) {
	t.Helper()
	bin, err := exec.LookPath("poetry")
	if err != nil {
		t.Fatalf("poetry not found in PATH — install poetry >= %d.%d to run these tests", minPoetryMajor, minPoetryMinor)
	}
	out, err := exec.Command(bin, "--version", "--no-ansi").Output()
	if err != nil {
		t.Fatalf("failed to run `poetry --version`: %v", err)
	}
	major, minor, patch, err := parsePoetryVersion(strings.TrimSpace(string(out)))
	require.NoError(t, err)
	if major < minPoetryMajor || (major == minPoetryMajor && minor < minPoetryMinor) {
		t.Fatalf("poetry %d.%d.%d is below the required minimum %d.%d", major, minor, patch, minPoetryMajor, minPoetryMinor)
	}
	t.Logf("poetry version: %d.%d.%d", major, minor, patch)
}

func TestAcceptance_Simple(t *testing.T) {
	requirePoetry(t)
	runAcceptanceFixture(t, "simple")
}

// runAcceptanceFixture executes the plugin against testdata/acceptance/<name>/
// and either updates the golden (with -update) or asserts the produced
// dep graph matches expected.json.
func runAcceptanceFixture(t *testing.T, name string) {
	t.Helper()

	dir := filepath.Join("testdata", "acceptance", name)
	require.DirExists(t, dir)

	// Snapshot the fixture directory before the run so we can assert
	// that poetry didn't create any of its install-time artefacts.
	before := snapshotDir(t, dir)

	plugin := Plugin{}
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "simple fixture must produce exactly one dep graph")
	require.NoError(t, results[0].Error)

	// Install-free assertion: poetry must not have created .venv/ or
	// dist/ or other install-side-effect directories.
	after := snapshotDir(t, dir)
	for _, forbidden := range []string{".venv", "dist", "build", "__pycache__"} {
		assert.NotContains(t, after, forbidden,
			"poetry show must not create %s/ in the project directory", forbidden)
	}
	assert.ElementsMatch(t, before, after, "poetry plugin must not mutate the project directory")

	dg := results[0].DepGraph
	require.NotNil(t, dg)

	goldenPath := filepath.Join(dir, "expected.json")
	if *updateGolden {
		data, mErr := json.MarshalIndent(dg, "", "  ")
		require.NoError(t, mErr, "marshaling dep graph")
		require.NoError(t, os.WriteFile(goldenPath, append(data, '\n'), 0o600))
		t.Logf("updated %s", goldenPath)
		return
	}

	raw, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "reading %s", goldenPath)
	expected, err := depgraph.UnmarshalJSON(raw)
	require.NoError(t, err, "parsing %s", goldenPath)

	assert.Equal(t, normalizedJSON(t, expected), normalizedJSON(t, dg))
}

// snapshotDir returns a sorted list of relative paths under dir. Used
// to assert the plugin doesn't mutate the project directory.
func snapshotDir(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out = append(out, rel)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(out)
	return out
}

// normalizedJSON marshals a dep graph to JSON with arrays sorted so
// equality checks aren't order-sensitive.
func normalizedJSON(t *testing.T, dg *depgraph.DepGraph) string {
	t.Helper()
	sort.Slice(dg.Pkgs, func(i, j int) bool { return dg.Pkgs[i].ID < dg.Pkgs[j].ID })
	sort.Slice(dg.Graph.Nodes, func(i, j int) bool { return dg.Graph.Nodes[i].NodeID < dg.Graph.Nodes[j].NodeID })
	for i := range dg.Graph.Nodes {
		sort.Slice(dg.Graph.Nodes[i].Deps, func(a, b int) bool {
			return dg.Graph.Nodes[i].Deps[a].NodeID < dg.Graph.Nodes[i].Deps[b].NodeID
		})
	}
	data, err := json.MarshalIndent(dg, "", "  ")
	require.NoError(t, err)
	return string(data)
}
