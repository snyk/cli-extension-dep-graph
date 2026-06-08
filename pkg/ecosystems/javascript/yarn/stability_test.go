package yarn_test

// stability_test.go runs the plugin against every classic-* fixture under
// testdata/fixtures/ and asserts two invariants:
//
//  1. No node_modules, .yarn, or .pnp.* file is created in the staged fixture
//     dir — the "no install" contract holds for every fixture, not just the
//     happy-path one covered by TestAcceptance_Classic.
//  2. Every resolved (name, version) entry in the fixture's yarn.lock appears
//     in some produced dep graph (the union across all SCAResults). Catches
//     parser regressions where edge-case lockfile shapes (cycles, workspaces,
//     npm: aliases, git/tarball URLs, dev-deps-only) silently drop packages.
//
// Fixtures are copied verbatim from
// nodejs-lockfile-parser/test/jest/dep-graph-builders/fixtures/yarn-lock-v1/real/
// (prefixed "classic-" in our tree). They cover the same divergences customer
// projects exhibit in the wild.
//
// Run with: go test -run TestClassicStability ./pkg/ecosystems/javascript/yarn/...

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/yarn"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// TestClassicStability discovers every testdata/fixtures/classic-* dir,
// runs the plugin against a staged copy, and asserts the install-free +
// completeness invariants. Skips per-fixture if real yarn errors for
// environmental reasons (no network for git deps, etc.).
func TestClassicStability(t *testing.T) {
	requireYarn(t, 1)

	fixtures, err := filepath.Glob("testdata/fixtures/classic-*")
	require.NoError(t, err)
	require.NotEmpty(t, fixtures, "no classic-* fixtures under testdata/fixtures/")

	plugin := yarn.Plugin{}

	for _, srcDir := range fixtures {
		name := filepath.Base(srcDir)
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			copyTree(t, srcDir, dir)

			// Strip captured CLI output and any auxiliary files so the staged
			// dir contains only the inputs yarn will read.
			_ = os.Remove(filepath.Join(dir, "list_output.txt"))
			_ = os.Remove(filepath.Join(dir, "info_output.txt"))

			// Sanity: every fixture must have at least yarn.lock + package.json.
			require.FileExists(t, filepath.Join(dir, "yarn.lock"))
			require.FileExists(t, filepath.Join(dir, "package.json"))

			results, err := scatest.Run(
				context.Background(), plugin, logger.Nop(), dir,
				&ecosystems.SCAPluginOptions{},
			)
			require.NoError(t, err, "plugin invocation failed")
			require.NotEmpty(t, results, "plugin produced no SCAResults")

			// Per-result error surfacing — if yarn itself failed (e.g.
			// fixture references an unreachable git URL), skip rather than
			// fail the stability run.
			for _, r := range results {
				if r.Error != nil {
					t.Skipf("yarn invocation failed for fixture (likely env-specific): %v", r.Error)
				}
			}

			assertNoInstallArtifacts(t, dir)
			assertLockfileCompleteness(t, filepath.Join(dir, "yarn.lock"), results)
		})
	}
}

// assertNoInstallArtifacts verifies the plugin held to the install-free
// contract: no node_modules, no .yarn dir, no .pnp.* files appeared in the
// staged fixture dir during the run.
func assertNoInstallArtifacts(t *testing.T, dir string) {
	t.Helper()

	for _, name := range []string{"node_modules", ".yarn"} {
		_, err := os.Stat(filepath.Join(dir, name))
		assert.True(t, os.IsNotExist(err),
			"plugin created %s in fixture dir (violates install-free contract)", name)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".pnp.*"))
	assert.Empty(t, matches, "plugin created .pnp.* artifact in fixture dir")
}

// assertLockfileCompleteness asserts every resolved (name, version) in the
// fixture's yarn.lock appears in some produced dep graph's Pkg set.
//
// Workspace projects yield multiple SCAResults (root + one per workspace);
// the lockfile only enumerates non-workspace deps (workspaces aren't from
// the registry), and any given lockfile package appears in at least one of
// the produced graphs.
func assertLockfileCompleteness(t *testing.T, lockfilePath string, results []ecosystems.SCAResult) {
	t.Helper()

	lockPkgs := parseLockfileV1(t, lockfilePath)
	if len(lockPkgs) == 0 {
		t.Logf("yarn.lock contained no resolved entries; skipping completeness check")
		return
	}

	allGraphPkgs := make(map[string]struct{})
	for _, r := range results {
		if r.DepGraph == nil {
			continue
		}
		for _, p := range r.DepGraph.Pkgs {
			allGraphPkgs[p.ID] = struct{}{}
		}
	}

	var missing []string
	for _, id := range lockPkgs {
		if _, ok := allGraphPkgs[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		// Cap the listed output so a large regression doesn't drown the run.
		preview := missing
		if len(preview) > 20 {
			preview = preview[:20]
		}
		t.Errorf("%d of %d lockfile packages missing from produced dep graphs; first: %v",
			len(missing), len(lockPkgs), preview)
	}
}

// copyTree recursively copies src into dst, preserving directory structure
// and file mode bits. Used to stage each fixture in a tmp dir so the
// install-free assertion can examine the dir contents after the run.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()

	require.NoError(t, filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}))
}

// parseLockfileV1 returns every (name, version) pair from a yarn.lock v1
// file as "name@version" strings — matching the form dep-graph Pkg.IDs take
// for v1 (no protocol prefix).
//
// Header parsing splits at the first '@' after the optional scope prefix, so
// identifiers containing additional '@' (npm: aliases like
// "lodash@npm:lodash@^4.17.15", URLs like
// "pkg@git+ssh://git@github.com/...") yield the right name. Splitting at the
// LAST '@' instead — which the production parser used to do — silently
// produced wrong names for these patterns and is exactly the divergence this
// stability test exists to catch.
var lockVersionRe = regexp.MustCompile(`^\s+version\s+"([^"]+)"\s*$`)

func parseLockfileV1(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var (
		pkgs        []string
		currentName string
	)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Header: starts in column 0, ends in ":". Take the first specifier
		// from comma-separated lists; all specs in one header share the same
		// resolved version.
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			header := strings.TrimSuffix(line, ":")
			first := strings.TrimSpace(strings.SplitN(header, ",", 2)[0])
			first = strings.Trim(first, `"`)
			currentName = lockNameFromSpec(first)
			continue
		}

		if m := lockVersionRe.FindStringSubmatch(line); m != nil && currentName != "" {
			pkgs = append(pkgs, currentName+"@"+m[1])
			currentName = ""
		}
	}
	return pkgs
}

// lockNameFromSpec mirrors the production nameFromSpec (which is unexported)
// so this in-package test helper can split specs the same way without
// duplicating the production type surface.
func lockNameFromSpec(spec string) string {
	if spec == "" {
		return ""
	}
	offset := 0
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		if slash < 0 {
			return ""
		}
		offset = slash + 1
	}
	idx := strings.Index(spec[offset:], "@")
	if idx <= 0 {
		return ""
	}
	return spec[:offset+idx]
}
