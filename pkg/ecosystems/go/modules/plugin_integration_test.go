//go:build integration && gomodules
// +build integration,gomodules

package modules_test

// plugin_integration_test.go verifies the go modules plugin against
// fixtures in testdata/acceptance/. Each fixture directory contains a
// go.mod (+ go.sum if it has external deps) and an expected.json
// capturing the dep graph the plugin produces.
//
// Build tag `integration && gomodules` keeps these tests out of the
// default `go test ./...` run — they require real `go` in PATH and
// the fixture's modules to be present in the local cache (since the
// plugin runs `go list` with GOPROXY=off).
//
// Run with `make test-gomodules-integration`, or directly via
//
//	go test -tags=integration,gomodules -v ./pkg/ecosystems/go/modules/...
//
// Regenerate goldens with `-update`.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
	gomodules "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/go/modules"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var updateGolden = flag.Bool("update", false, "overwrite expected.json golden files with current plugin output")

// requireGo skips the suite if the `go` binary is not on PATH.
func requireGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go not found in PATH — install Go to run these tests")
	}
}

// TestAcceptance_Simple runs the single-module fixture and asserts:
//   - the plugin produces exactly one SCAResult
//   - the dep graph matches the golden expected.json
//   - the plugin's offline contract is respected: no entries are
//     added to $GOPATH/pkg/mod and no vendor/ tree appears.
func TestAcceptance_Simple(t *testing.T) {
	requireGo(t)

	dir := filepath.Join("testdata", "acceptance", "simple")

	beforeMod := snapshotModCache(t)
	beforeVendor := vendorExists(dir)

	plugin := gomodules.Plugin{}
	results, err := scatest.Run(context.Background(), plugin, nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)

	assertNoCacheGrowth(t, beforeMod)
	assert.Equal(t, beforeVendor, vendorExists(dir), "fixture vendor/ must not be created by the plugin")

	if *updateGolden {
		writeGolden(t, filepath.Join(dir, "expected.json"), results[0].DepGraph)
		return
	}

	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	require.NoError(t, err, "reading expected.json")

	expected, err := depgraph.UnmarshalJSON(raw)
	require.NoError(t, err, "parsing expected.json")

	assert.Equal(t, normalizedJSON(expected), normalizedJSON(results[0].DepGraph))
}

// TestAcceptance_Workspace runs the go.work fixture and asserts one
// SCAResult per workspace member, each matching a golden file named
// after the member.
func TestAcceptance_Workspace(t *testing.T) {
	requireGo(t)

	dir := filepath.Join("testdata", "acceptance", "workspace")

	beforeMod := snapshotModCache(t)
	beforeVendor := vendorExists(dir)

	plugin := gomodules.Plugin{}
	results, err := scatest.Run(context.Background(), plugin, nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 2, "one SCAResult per workspace member")

	assertNoCacheGrowth(t, beforeMod)
	assert.Equal(t, beforeVendor, vendorExists(dir), "fixture vendor/ must not be created by the plugin")

	byMember := make(map[string]*depgraph.DepGraph)
	for _, r := range results {
		require.NoError(t, r.Error)
		// Use the member dir (svc-a, svc-b) as the index.
		member := filepath.Base(filepath.Dir(r.ProjectDescriptor.GetTargetFile()))
		byMember[member] = r.DepGraph
	}

	for _, member := range []string{"svc-a", "svc-b"} {
		t.Run(member, func(t *testing.T) {
			dg, ok := byMember[member]
			require.True(t, ok, "no SCAResult for member %s", member)

			goldenPath := filepath.Join(dir, "expected-"+member+".json")

			if *updateGolden {
				writeGolden(t, goldenPath, dg)
				return
			}

			raw, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "reading %s", goldenPath)

			expected, err := depgraph.UnmarshalJSON(raw)
			require.NoError(t, err, "parsing %s", goldenPath)

			assert.Equal(t, normalizedJSON(expected), normalizedJSON(dg), "mismatch in %s", goldenPath)
		})
	}
}

// snapshotModCache lists the immediate children of $GOPATH/pkg/mod
// (or $GOMODCACHE if set) at the moment of capture. Returns nil if
// the cache dir doesn't exist — assertion is treated as "no entries
// before, none after" in that case.
func snapshotModCache(t *testing.T) map[string]struct{} {
	t.Helper()
	cache := goModCacheDir(t)
	entries, err := os.ReadDir(cache)
	if err != nil {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		out[e.Name()] = struct{}{}
	}
	return out
}

// assertNoCacheGrowth compares the current mod cache contents against
// a prior snapshot and fails if any new entries appear. This is the
// offline / install-free contract for the plugin: with GOPROXY=off it
// MUST NOT cause modules to be downloaded.
func assertNoCacheGrowth(t *testing.T, before map[string]struct{}) {
	t.Helper()
	after := snapshotModCache(t)
	var added []string
	for k := range after {
		if _, ok := before[k]; !ok {
			added = append(added, k)
		}
	}
	if len(added) > 0 {
		sort.Strings(added)
		t.Fatalf("plugin added %d entries to the module cache: %v", len(added), added)
	}
}

// goModCacheDir returns the active module cache directory, preferring
// $GOMODCACHE then falling back to $GOPATH/pkg/mod then ~/go/pkg/mod.
func goModCacheDir(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("GOMODCACHE"); v != "" {
		return v
	}
	if v := os.Getenv("GOPATH"); v != "" {
		return filepath.Join(strings.Split(v, string(os.PathListSeparator))[0], "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("could not determine home dir: %v", err)
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

// vendorExists reports whether dir contains a vendor/ directory.
func vendorExists(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "vendor"))
	return err == nil && info.IsDir()
}

// writeGolden persists a dep graph to the given path as canonical JSON.
func writeGolden(t *testing.T, path string, dg *depgraph.DepGraph) {
	t.Helper()
	data, err := json.MarshalIndent(dg, "", "  ")
	require.NoError(t, err, "marshaling dep graph")
	require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o600), "writing %s", path)
	t.Logf("updated %s", path)
}

// normalizedJSON marshals a dep graph to JSON with all arrays sorted,
// so comparisons are order-independent.
func normalizedJSON(dg *depgraph.DepGraph) string {
	sort.Slice(dg.Pkgs, func(i, j int) bool { return dg.Pkgs[i].ID < dg.Pkgs[j].ID })
	sort.Slice(dg.Graph.Nodes, func(i, j int) bool { return dg.Graph.Nodes[i].NodeID < dg.Graph.Nodes[j].NodeID })

	for i := range dg.Graph.Nodes {
		sort.Slice(dg.Graph.Nodes[i].Deps, func(a, b int) bool {
			return dg.Graph.Nodes[i].Deps[a].NodeID < dg.Graph.Nodes[i].Deps[b].NodeID
		})
	}

	data, err := json.MarshalIndent(dg, "", "  ")
	if err != nil {
		panic(fmt.Errorf("marshaling normalised dep graph: %w", err))
	}
	return string(data)
}
