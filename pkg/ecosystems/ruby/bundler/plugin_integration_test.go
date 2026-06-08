//go:build integration && bundler
// +build integration,bundler

package bundler_test

// plugin_integration_test.go verifies the bundler plugin against golden
// dep graphs stored in testdata/acceptance/. Each fixture directory
// contains a Gemfile.lock (and optionally a Gemfile/.gemspec) plus an
// expected.json capturing the dep graph the plugin produces.
//
// Unlike most ecosystems' integration tests, no external tool is
// required: the bundler plugin parses Gemfile.lock natively. The build
// tag `integration && bundler` is preserved for parity with the rest
// of the suite and to keep these fixtures out of the default `go test
// ./...` run while we iterate on the divergence corpus.
//
// Run with:
//   go test -v -tags="integration,bundler" ./pkg/ecosystems/ruby/bundler/...
// Update goldens:
//   go test -v -tags="integration,bundler" -run TestAcceptance \
//       ./pkg/ecosystems/ruby/bundler/... -update

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
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	bundlerpkg "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/ruby/bundler"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var updateGolden = flag.Bool("update", false, "overwrite expected.json golden files with current plugin output")

type fixture struct {
	name string
	dir  string
}

// discoverFixtures finds every directory under base that contains a
// Gemfile.lock — this is what makes the suite extensible (drop a new
// directory in, it gets picked up).
func discoverFixtures(t *testing.T, base string) []fixture {
	t.Helper()
	entries, err := os.ReadDir(base)
	require.NoError(t, err, "reading %s", base)

	out := make([]fixture, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "Gemfile.lock")); err != nil {
			continue
		}
		out = append(out, fixture{name: e.Name(), dir: dir})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// TestAcceptance runs every smoke fixture under testdata/acceptance/
// against the plugin and compares to its expected.json golden.
//
// Critically: the test ALSO asserts that no install artefacts
// (`vendor/`, `.bundle/`) appear in the fixture directory after the
// run. Bundler's `install` family of subcommands would create those;
// the native parser must never. This is the principle-#2 ("install
// free") gate for this ecosystem.
func TestAcceptance(t *testing.T) {
	fixtures := discoverFixtures(t, filepath.Join("testdata", "acceptance"))
	require.NotEmpty(t, fixtures, "no fixtures discovered")

	plugin := bundlerpkg.Plugin{}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			assertNoInstallArtefacts(t, fx.dir, "before run")

			results, err := scatest.Run(context.Background(), plugin, logger.Nop(), fx.dir,
				ecosystems.NewPluginOptions())
			require.NoError(t, err)
			require.Len(t, results, 1, "bundler emits exactly one graph per Gemfile.lock")

			r := results[0]
			require.NoError(t, r.Error)
			require.NotNil(t, r.DepGraph)

			assertNoInstallArtefacts(t, fx.dir, "after run — native parser must not install")

			goldenPath := filepath.Join(fx.dir, "expected.json")
			if *updateGolden {
				data, err := json.MarshalIndent(r.DepGraph, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(goldenPath, append(data, '\n'), 0o600))
				t.Logf("updated %s", goldenPath)
				return
			}

			raw, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "reading %s", goldenPath)
			expected, err := depgraph.UnmarshalJSON(raw)
			require.NoError(t, err, "parsing %s", goldenPath)

			assert.Equal(t,
				normalizedJSON(t, expected),
				normalizedJSON(t, r.DepGraph),
				"dep graph mismatch in %s — re-run with -update to refresh", fx.name)
		})
	}
}

// assertNoInstallArtefacts is the principle-#2 gate: native parsing
// must never create vendor/, .bundle/, or similar install side-effects
// in the fixture directory. If this ever fires, something invoked
// `bundle install` (or an equivalent) which it must not.
func assertNoInstallArtefacts(t *testing.T, dir, when string) {
	t.Helper()
	for _, artefact := range []string{"vendor", ".bundle"} {
		path := filepath.Join(dir, artefact)
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("install artefact %q exists in %s (%s) — the bundler plugin must never install",
				artefact, dir, when)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %q: %v", path, err)
		}
	}
}

// normalizedJSON re-marshals a dep graph through the canonical JSON
// shape so two equivalent graphs (e.g. dep order differing in a way
// the schema doesn't pin) compare equal. The Pkgs and per-node Deps
// arrays are sorted; everything else is left as-is.
func normalizedJSON(t *testing.T, dg *depgraph.DepGraph) string {
	t.Helper()
	// Round-trip through JSON to a generic map so we can sort
	// schema-flexible arrays without leaking depgraph internals.
	data, err := json.Marshal(dg)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	if pkgs, ok := m["pkgs"].([]any); ok {
		sort.Slice(pkgs, func(i, j int) bool {
			return pkgID(pkgs[i]) < pkgID(pkgs[j])
		})
	}
	if g, ok := m["graph"].(map[string]any); ok {
		if nodes, ok := g["nodes"].([]any); ok {
			sort.Slice(nodes, func(i, j int) bool {
				return nodeID(nodes[i]) < nodeID(nodes[j])
			})
			for _, n := range nodes {
				if nm, ok := n.(map[string]any); ok {
					if deps, ok := nm["deps"].([]any); ok {
						sort.Slice(deps, func(i, j int) bool {
							return nodeID(deps[i]) < nodeID(deps[j])
						})
					}
				}
			}
		}
	}

	out, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	return string(out)
}

func pkgID(v any) string {
	m, _ := v.(map[string]any)
	id, _ := m["id"].(string)
	return id
}

func nodeID(v any) string {
	m, _ := v.(map[string]any)
	if id, ok := m["nodeId"].(string); ok {
		return id
	}
	return ""
}
