package nuget_test

// acceptance_test.go runs the .NET plugin over the fixture projects in
// testdata/acceptance and diffs each dep graph against a committed golden file.
// See that directory's README.md for what each case covers and how to
// regenerate the goldens.
//
// Unlike the other ecosystems' acceptance suites this one needs no toolchain:
// the resolver only reads `dotnet restore` output, and that output is committed.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/dotnet/nuget"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var updateGolden = flag.Bool("update", false, "overwrite the expected*.json golden files with the current plugin output")

const acceptanceDir = "testdata/acceptance"

func TestAcceptance(t *testing.T) {
	fixtures := discoverFixtures(t, acceptanceDir)
	require.NotEmpty(t, fixtures, "no acceptance fixtures found under %s", acceptanceDir)

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(acceptanceDir, name)

			results, err := scatest.Run(t.Context(), nuget.Plugin{}, logger.Nop(), dir, fixtureOptions(t, dir))
			require.NoError(t, err)
			require.NotEmpty(t, results, "the plugin produced no results for %s", name)

			byRuntime := make(map[string]*godepgraph.DepGraph, len(results))

			for _, result := range results {
				require.NoError(t, result.Error, "%s produced an error result", name)
				require.NotNil(t, result.DepGraph)

				runtime := result.ProjectDescriptor.Identity.TargetRuntime
				require.NotNil(t, runtime, "every result must carry a target runtime")

				_, duplicate := byRuntime[*runtime]
				require.False(t, duplicate, "two results reported the same target runtime %q", *runtime)

				byRuntime[*runtime] = result.DepGraph
			}

			if *updateGolden {
				writeGoldens(t, dir, byRuntime)
				return
			}

			compareGoldens(t, dir, byRuntime)
		})
	}
}

// fixtureOptions builds the options a fixture is scanned with.
//
// A fixture with a packages/ directory gets --packages-folder pointing at a
// materialized copy of it. The derived default is the manifest's grandparent,
// which here would be testdata/acceptance itself.
func fixtureOptions(t *testing.T, dir string) *ecosystems.SCAPluginOptions {
	t.Helper()

	options := ecosystems.NewPluginOptions()

	packages := filepath.Join(dir, "packages")
	if _, err := os.Stat(packages); err != nil {
		return options
	}

	return options.WithPackagesFolder(materializePackages(t, packages))
}

// materializePackages copies a fixture's packages folder into a temp directory,
// zipping each committed .nuspec into the .nupkg that `nuget restore` would
// have written.
//
// The .nuspec files are committed as plain XML rather than the archives
// themselves so that a reviewer can read what a fixture claims, and so that
// changing it is a diff rather than a new binary.
func materializePackages(t *testing.T, source string) string {
	t.Helper()

	target := t.TempDir()

	entries, err := os.ReadDir(source)
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		packageDir := filepath.Join(target, entry.Name())
		require.NoError(t, os.MkdirAll(packageDir, 0o750))

		nuspec := filepath.Join(source, entry.Name(), entry.Name()+".nuspec")

		content, err := os.ReadFile(nuspec)
		if os.IsNotExist(err) {
			// An installed package with no .nuspec beside it: enough to
			// override a version, with no dependencies to contribute.
			continue
		}
		require.NoError(t, err)

		writeNupkgArchive(t, filepath.Join(packageDir, entry.Name()+".nupkg"), entry.Name()+".nuspec", content)
	}

	return target
}

// writeNupkgArchive writes a .nupkg holding a single .nuspec entry.
func writeNupkgArchive(t *testing.T, path, name string, content []byte) {
	t.Helper()

	var buf bytes.Buffer

	archive := zip.NewWriter(&buf)
	writer, err := archive.Create(name)
	require.NoError(t, err)
	_, err = writer.Write(content)
	require.NoError(t, err)
	require.NoError(t, archive.Close())

	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

// discoverFixtures lists the fixture directories under base.
func discoverFixtures(t *testing.T, base string) []string {
	t.Helper()

	entries, err := os.ReadDir(base)
	require.NoError(t, err, "reading %s", base)

	var names []string

	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}

	return names
}

// goldenPath names a golden after the target runtime its graph was reported
// under, always — including for a single-framework project.
//
// The runtime is the string the platform uses to tell a project's frameworks
// apart, and it is not part of the dep graph, so putting it in the filename is
// what pins it. With a bare expected.json a resolver reporting the raw `targets`
// key (".NETStandard,Version=v2.1") instead of the moniker the project declared
// ("netstandard2.1") would leave every golden untouched.
func goldenPath(dir, runtime string) string {
	return filepath.Join(dir, "expected-"+runtime+".json")
}

func compareGoldens(t *testing.T, dir string, byRuntime map[string]*godepgraph.DepGraph) {
	t.Helper()

	// A golden file with no matching result would otherwise pass unnoticed,
	// which is exactly how a dropped target framework hides.
	pattern := filepath.Join(dir, "expected*.json")
	golden, err := filepath.Glob(pattern)
	require.NoError(t, err)
	require.Len(t, golden, len(byRuntime),
		"%s has %d golden files but the plugin produced %d graphs; run with -update", dir, len(golden), len(byRuntime))

	for runtime, graph := range byRuntime {
		path := goldenPath(dir, runtime)

		want, err := os.ReadFile(path)
		require.NoError(t, err, "missing golden file %s; run with -update to create it", path)

		assert.JSONEq(t, string(want), string(normalise(t, graph)), "dep graph for %s changed", runtime)
	}
}

func writeGoldens(t *testing.T, dir string, byRuntime map[string]*godepgraph.DepGraph) {
	t.Helper()

	before, err := filepath.Glob(filepath.Join(dir, "expected*.json"))
	require.NoError(t, err)

	// Written before the stale ones are removed: deleting first means a failure
	// part-way through leaves the fixture with no golden and nothing to restore
	// it from, silently disarming the count check in compareGoldens.
	written := make(map[string]struct{}, len(byRuntime))

	for runtime, graph := range byRuntime {
		path := goldenPath(dir, runtime)
		require.NoError(t, os.WriteFile(path, append(normalise(t, graph), '\n'), 0o600))
		written[path] = struct{}{}
		t.Logf("wrote %s", path)
	}

	for _, path := range before {
		if _, kept := written[path]; kept {
			continue
		}

		require.NoError(t, os.Remove(path))
		t.Logf("removed stale %s", path)
	}
}

// normalise sorts packages, nodes and each node's dependencies before
// marshaling, so a golden file records the graph's content rather than the
// order the resolver happened to emit it in.
func normalise(t *testing.T, graph *godepgraph.DepGraph) []byte {
	t.Helper()

	sorted := *graph

	sorted.Pkgs = slices.Clone(graph.Pkgs)
	sort.Slice(sorted.Pkgs, func(i, j int) bool { return sorted.Pkgs[i].ID < sorted.Pkgs[j].ID })

	sorted.Graph.Nodes = slices.Clone(graph.Graph.Nodes)
	sort.Slice(sorted.Graph.Nodes, func(i, j int) bool {
		return sorted.Graph.Nodes[i].NodeID < sorted.Graph.Nodes[j].NodeID
	})

	for i := range sorted.Graph.Nodes {
		// Cloned in place so an empty dependency list stays an empty list. A
		// nil one would serialize as null and misreport the resolver's output.
		deps := slices.Clone(sorted.Graph.Nodes[i].Deps)
		sort.Slice(deps, func(a, b int) bool { return deps[a].NodeID < deps[b].NodeID })
		sorted.Graph.Nodes[i].Deps = deps
	}

	out, err := json.MarshalIndent(sorted, "", "  ")
	require.NoError(t, err)

	return out
}
