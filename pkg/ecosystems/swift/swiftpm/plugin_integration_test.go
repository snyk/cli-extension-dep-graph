//go:build integration && swiftpm
// +build integration,swiftpm

package swiftpm_test

// plugin_integration_test.go verifies the swiftpm plugin against golden dep
// graphs stored in testdata/acceptance/. Each fixture directory contains a
// Package.swift, a Package.resolved (so swift can resolve fully offline from
// its global cache), and an expected.json capturing the dep graph the plugin
// emits.
//
// Build tag `integration && swiftpm` keeps these tests out of the default
// `go test ./...` run — they require real swift in PATH.
//
// Run with `make test-swiftpm-integration`, or directly via
//
//	go test -tags=integration,swiftpm -v ./pkg/ecosystems/swift/swiftpm/...
//
// Regenerate goldens with `-update`.
//
// Each fixture is copied to a fresh temp directory before the plugin runs.
// swift package show-dependencies always creates a .build/ checkouts tree
// alongside the manifest, so we cannot run it directly against the test
// source tree without permanently dirtying the repo. The temp-dir copy keeps
// the source untouched and lets us assert that no .build/ or .swiftpm/
// directory has appeared in the original fixture dir afterwards — the
// project-dir-immutability guarantee the spec calls for.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/swift/swiftpm"
)

var updateGolden = flag.Bool("update", false, "overwrite expected.json golden files with current plugin output")

type acceptanceFixture struct {
	name string
	dir  string
}

var testSwiftVersionRe = regexp.MustCompile(`Swift version (\d+)\.(\d+)(?:\.(\d+))?`)

const minTestSwiftVersion = "v5.6.0"

// requireSwift skips the test if swift is absent or older than the minimum
// supported toolchain; fails it if `swift --version` is present but
// unparseable.
func requireSwift(t *testing.T) {
	t.Helper()
	swiftPath, err := exec.LookPath("swift")
	if err != nil {
		t.Skipf("swift not found in PATH — install swift >= %s to run these tests", minTestSwiftVersion)
	}
	out, err := exec.Command(swiftPath, "--version").Output()
	if err != nil {
		t.Fatalf("failed to get swift version: %v", err)
	}
	raw := strings.TrimSpace(string(out))
	m := testSwiftVersionRe.FindStringSubmatch(raw)
	if m == nil {
		t.Fatalf("could not parse swift version from %q", raw)
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	ver := "v" + m[1] + "." + m[2] + "." + patch
	if semver.Compare(ver, minTestSwiftVersion) < 0 {
		t.Skipf("swift %s is below the required minimum %s", ver, minTestSwiftVersion)
	}
	t.Logf("swift version: %s", ver)
}

// TestAcceptance runs the swiftpm plugin against every fixture in
// testdata/acceptance/ and diff-checks the resulting dep graph against the
// committed golden.
//
// In addition to the dep-graph comparison, each subtest asserts that the
// source fixture directory is unmodified after the plugin runs — no
// .build/, no .swiftpm/, no Package.resolved written if one wasn't there
// already. The plugin must never mutate the project tree.
func TestAcceptance(t *testing.T) {
	requireSwift(t)

	fixtures := discoverFixtures(t, filepath.Join("testdata", "acceptance"))
	require.NotEmpty(t, fixtures, "no fixtures found")

	plugin := swiftpm.Plugin{}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			// Snapshot the source dir contents before doing anything so we
			// can compare after the plugin runs.
			before := snapshotDir(t, fx.dir)

			// Copy the fixture to a temp directory so swift's resolved-cache
			// side-effects (always written into .build/) don't dirty the
			// committed fixture.
			scratch := t.TempDir()
			copyTree(t, fx.dir, scratch)

			results, err := scatest.Run(context.Background(), plugin, nil, scratch, &ecosystems.SCAPluginOptions{})
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)

			// Acceptance assertion: the source fixture dir must be untouched.
			// swift package show-dependencies, when allowed to, always
			// creates .build/ — we route it at the temp copy so the source
			// stays clean.
			after := snapshotDir(t, fx.dir)
			assert.Equal(t, before, after,
				"source fixture must not be mutated; .build/ or .swiftpm/ would indicate the plugin is running swift against the source")
			assert.NoDirExists(t, filepath.Join(fx.dir, ".build"),
				"no .build/ directory must appear in the source fixture")
			assert.NoDirExists(t, filepath.Join(fx.dir, ".swiftpm"),
				"no .swiftpm/ directory must appear in the source fixture")

			if *updateGolden {
				writeGolden(t, filepath.Join(fx.dir, "expected.json"), results[0].DepGraph)
				return
			}

			raw, err := os.ReadFile(filepath.Join(fx.dir, "expected.json"))
			require.NoError(t, err, "reading expected.json")

			expected, err := depgraph.UnmarshalJSON(raw)
			require.NoError(t, err, "parsing expected.json")

			assert.Equal(t, normalizedJSON(expected), normalizedJSON(results[0].DepGraph))
		})
	}
}

// writeGolden persists a dep graph to the given path as canonical JSON.
func writeGolden(t *testing.T, path string, dg *depgraph.DepGraph) {
	t.Helper()
	data, err := json.MarshalIndent(dg, "", "  ")
	require.NoError(t, err, "marshaling dep graph")
	require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o600), "writing %s", path)
	t.Logf("updated %s", path)
}

// normalizedJSON marshals a dep graph to JSON with all arrays sorted, so
// comparisons are order-independent.
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

// discoverFixtures finds all fixture dirs that contain a Package.swift. We
// don't filter on expected.json so `-update` can seed brand-new fixtures.
func discoverFixtures(t *testing.T, base string) []acceptanceFixture {
	t.Helper()

	entries, err := os.ReadDir(base)
	require.NoError(t, err, "reading fixtures dir: %s", base)

	var fixtures []acceptanceFixture

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fxDir := filepath.Join(base, entry.Name())
		if _, err := os.Stat(filepath.Join(fxDir, "Package.swift")); err != nil {
			continue
		}

		fixtures = append(fixtures, acceptanceFixture{name: entry.Name(), dir: fxDir})
	}

	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].name < fixtures[j].name })

	return fixtures
}

// snapshotDir returns a sorted list of "relpath" entries under dir so two
// snapshots compare cleanly. Compares structure only, not content — the
// only mutation we're guarding against is swift creating .build/ /
// .swiftpm/ checkout caches.
func snapshotDir(t *testing.T, dir string) []string {
	t.Helper()
	var entries []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		entries = append(entries, rel)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(entries)
	return entries
}

// copyTree mirrors src into dst, preserving file modes.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	require.NoError(t, filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target, info.Mode())
	}))
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
