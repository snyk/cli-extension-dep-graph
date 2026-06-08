//go:build integration && cocoapods

// plugin_integration_test.go drives the cocoapods plugin against
// real Podfile.lock fixtures under testdata/acceptance/ and compares
// produced dep graphs to committed expected.json goldens.
//
// Run with: `make test-cocoapods-integration`
//
// Refresh goldens after intentional plugin changes:
//
//	go test -tags="integration,cocoapods" \
//	  ./pkg/ecosystems/cocoa/cocoapods/... -run TestAcceptance -update
//
// The build tag combination (`integration && cocoapods`) keeps these
// tests out of the default `go test ./...` run — they live next to
// the unit tests but stay invisible until both tags are set.
package cocoapods_test

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/cocoa/cocoapods"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var updateGolden = flag.Bool("update", false, "overwrite expected.json golden files with current plugin output")

// TestAcceptance walks every directory under testdata/acceptance/ that
// contains a Podfile.lock and verifies the produced dep graph matches
// the committed expected.json. With -update it overwrites the goldens
// instead of comparing.
func TestAcceptance(t *testing.T) {
	fixtures := discoverFixtures(t, filepath.Join("testdata", "acceptance"))
	require.NotEmpty(t, fixtures, "no fixtures found under testdata/acceptance")

	for _, fx := range fixtures {
		t.Run(fx, func(t *testing.T) {
			dir := filepath.Join("testdata", "acceptance", fx)

			results, err := scatest.Run(context.Background(), cocoapods.Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)

			// Sanity: native parsing must NEVER mutate the project
			// directory. CocoaPods install would create Pods/.
			assert.NoDirExists(t, filepath.Join(dir, "Pods"),
				"native parsing must not create a Pods/ directory")

			if *updateGolden {
				data, mErr := json.MarshalIndent(results[0].DepGraph, "", "  ")
				require.NoError(t, mErr)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "expected.json"), append(data, '\n'), 0o600))
				t.Logf("updated %s/expected.json", fx)
				return
			}

			raw, rErr := os.ReadFile(filepath.Join(dir, "expected.json"))
			require.NoError(t, rErr, "reading expected.json (run with -update to generate)")

			expected, pErr := depgraph.UnmarshalJSON(raw)
			require.NoError(t, pErr)

			assert.Equal(t, normalizedJSON(expected), normalizedJSON(results[0].DepGraph))
		})
	}
}

// discoverFixtures returns the names of subdirectories of base that
// contain a Podfile.lock — those are the fixture directories.
func discoverFixtures(t *testing.T, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(base)
	require.NoError(t, err, "reading fixtures dir: %s", base)

	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, sErr := os.Stat(filepath.Join(base, e.Name(), "Podfile.lock")); sErr != nil {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// normalizedJSON marshals a dep graph with arrays sorted so comparisons
// are order-independent (PkgManager.Repositories order is non-deterministic
// because it comes from a Go map).
func normalizedJSON(dg *depgraph.DepGraph) string {
	sort.Slice(dg.Pkgs, func(i, j int) bool { return dg.Pkgs[i].ID < dg.Pkgs[j].ID })
	sort.Slice(dg.Graph.Nodes, func(i, j int) bool { return dg.Graph.Nodes[i].NodeID < dg.Graph.Nodes[j].NodeID })
	for i := range dg.Graph.Nodes {
		sort.Slice(dg.Graph.Nodes[i].Deps, func(a, b int) bool {
			return dg.Graph.Nodes[i].Deps[a].NodeID < dg.Graph.Nodes[i].Deps[b].NodeID
		})
	}
	sort.Slice(dg.PkgManager.Repositories, func(i, j int) bool {
		return dg.PkgManager.Repositories[i].Alias < dg.PkgManager.Repositories[j].Alias
	})

	data, err := json.MarshalIndent(dg, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(data)
}
