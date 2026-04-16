package bun_test

// stability_test.go verifies that the bun plugin continues to parse `bun why`
// output correctly across bun releases. Unlike the acceptance tests, it does
// NOT compare against golden files — it only checks that every package present
// in bun.lock also appears in the dep graph produced by the plugin.
//
// The intent is to run this daily against the latest bun binary (see
// .github/workflows/bun-why-stability.yml). A failure means bun changed its
// `bun why '*' --top` output format in a way that breaks the parser, giving us
// early warning before users are affected.
//
// Run manually with:
//
//	go test -v -count=1 -run TestBunWhyOutputStability ./pkg/ecosystems/javascript/bun/...

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/javascript/bun"
)

// TestBunWhyOutputStability runs the plugin against every fixture directory
// that has a bun.lock and asserts:
//
//  1. BuildDepGraphsFromDir returns no error and no per-result errors.
//  2. Every package listed in bun.lock appears in at least one dep graph.
//
// Condition 2 catches silent regressions where the parser produces a valid but
// incomplete graph — e.g. if bun changes indentation or tree characters so that
// depth-1 lines no longer match the regex.
func TestBunWhyOutputStability(t *testing.T) {
	if _, err := exec.LookPath("bun"); err != nil {
		t.Skip("bun not found in PATH — skipping stability test")
	}

	// Log the bun version prominently so CI failure logs are easy to diagnose.
	if out, err := exec.Command("bun", "--version").Output(); err == nil {
		t.Logf("bun version: %s", strings.TrimSpace(string(out)))
	}

	plugin := bun.Plugin{}
	opts := &ecosystems.SCAPluginOptions{}

	entries, err := os.ReadDir(filepath.Join("testdata", "acceptance"))
	require.NoError(t, err, "reading testdata/acceptance")

	testedAtLeastOne := false

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dir := filepath.Join("testdata", "acceptance", entry.Name())
		if _, statErr := os.Stat(filepath.Join(dir, "bun.lock")); statErr != nil {
			continue
		}

		testedAtLeastOne = true

		t.Run(entry.Name(), func(t *testing.T) {
			result, err := plugin.BuildDepGraphsFromDir(t.Context(), nil, dir, opts)
			require.NoError(t, err, "BuildDepGraphsFromDir returned an unexpected error")
			require.NotEmpty(t, result.Results, "plugin produced no results for %s", entry.Name())

			for i, r := range result.Results {
				assert.NoError(t, r.Error, "result[%d] for %s contains an error", i, entry.Name())
			}

			// Verify every package in bun.lock is present in some dep graph.
			// A non-empty missing list is the primary signal of a parser regression.
			missing := lockfilePackagesMissingFromGraph(t, dir, allResultPkgs(result.Results))
			for _, id := range missing {
				t.Errorf("bun.lock package %q missing from dep graph — possible bun why format regression", id)
			}
		})
	}

	require.True(t, testedAtLeastOne, "no fixture directories with bun.lock found — check testdata/acceptance/")
}
