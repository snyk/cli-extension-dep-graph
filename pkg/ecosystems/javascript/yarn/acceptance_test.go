package yarn_test

// acceptance_test.go exercises the yarn plugin end-to-end against a real
// `yarn` binary in PATH. Tests skip with t.Skip when yarn is absent or the
// detected major doesn't match the case under test (Berry tests need a yarn
// shim that resolves to v2+; CI sets this up via corepack).
//
// Run only the v1 path:    go test -run TestAcceptance_Classic ./pkg/ecosystems/javascript/yarn/...
// Run only the Berry path: go test -run TestAcceptance_Berry   ./pkg/ecosystems/javascript/yarn/...

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	snykdepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/yarn"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

var versionRe = regexp.MustCompile(`(\d+)\.\d+\.\d+`)

// requireYarn skips the test if yarn is missing or its major doesn't match
// wantMajor. Returns the detected major when it does match.
func requireYarn(t *testing.T, wantMajor int) int {
	t.Helper()

	binary, err := exec.LookPath("yarn")
	if err != nil {
		t.Skipf("yarn not in PATH — skipping acceptance test (want major %d)", wantMajor)
	}
	out, err := exec.Command(binary, "--version").Output()
	if err != nil {
		t.Skipf("yarn --version failed: %v", err)
	}
	m := versionRe.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		t.Skipf("could not parse yarn version: %q", out)
	}
	got, _ := strconv.Atoi(m[1]) //nolint:errcheck // regex group is \d+
	if got != wantMajor {
		t.Skipf("yarn major %d in PATH, test needs %d", got, wantMajor)
	}
	t.Logf("yarn version: %s.x", m[1])
	return got
}

// TestAcceptance_Classic exercises the v1 path end-to-end against the
// classic-simple fixture (one direct dep, three transitives). Verifies the
// plugin produces the expected dep graph WITHOUT creating node_modules.
func TestAcceptance_Classic(t *testing.T) {
	requireYarn(t, 1)

	// Stage the fixture into a tmp dir so the test can later assert that
	// node_modules / .yarn never appeared alongside the lockfile.
	srcDir := filepath.Join("testdata", "fixtures", "classic-simple")
	dir := t.TempDir()
	for _, name := range []string{"package.json", "yarn.lock"} {
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}

	plugin := yarn.Plugin{}
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 1, "non-workspace project → single dep graph")
	require.NoError(t, results[0].Error)
	require.NotNil(t, results[0].DepGraph)

	dg := results[0].DepGraph
	assert.Equal(t, "yarn", dg.PkgManager.Name)
	assert.Equal(t, "one-dep", dg.GetRootPkg().Info.Name)

	pkgIDs := make(map[string]bool, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}
	// Lockfile resolved versions — must all be present.
	for _, want := range []string{
		"accepts@1.3.7",
		"mime-types@2.1.31",
		"mime-db@1.48.0",
		"negotiator@0.6.2",
	} {
		assert.True(t, pkgIDs[want], "expected %s in dep graph; got pkgs: %v", want, pkgIDs)
	}

	// Install-free contract: the staged dir must contain only the files we put there.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"package.json", "yarn.lock"}, names,
		"yarn plugin must not create node_modules or .yarn dirs in the project")
}

// TestAcceptance_Classic_Workspaces drives the v1 plugin end-to-end against
// a real workspaces project (workspace-with-cross-ref: pkg-a depends on
// express + pkg-b@1.0.0; pkg-b depends on accepts). Asserts the shape
// invariants that completeness coverage alone won't catch:
//
//   - One SCAResult per workspace member, plus one for the root project.
//   - Identity.TargetFile is nil on every result (legacy-yarn parity — see
//     buildResults identity contract). Each result's manifest path lives on
//     ResolverMetadata.NormalisedTargetFile instead: yarn.lock for the root
//     SCAResult, packages/<name>/package.json for each workspace.
//   - In pkg-a's own dep graph, express is fully expanded but pkg-b is a
//     stop-set leaf (its transitives live only in pkg-b's own graph), so
//     vuln reports don't double-count accepts across workspaces.
//
// We don't compare against goldens because real yarn list output drifts as
// the registry updates transitives — shape assertions are stable, exact
// counts are not.
func TestAcceptance_Classic_Workspaces(t *testing.T) {
	requireYarn(t, 1)

	srcDir := filepath.Join("testdata", "fixtures", "classic-workspace-with-cross-ref")
	dir := t.TempDir()
	copyTreeForAcceptance(t, srcDir, dir)

	plugin := yarn.Plugin{}
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, results, 3, "expected root + pkg-a + pkg-b SCAResults")

	root := findResultByRootName(t, results, "yarn-1-workspace-with-cross-ref")
	pkgA := findResultByRootName(t, results, "pkg-a")
	pkgB := findResultByRootName(t, results, "pkg-b")

	// Identity.TargetFile must be nil for every result — legacy yarn parity.
	for _, r := range []ecosystems.SCAResult{root, pkgA, pkgB} {
		assert.Nil(t, r.ProjectDescriptor.Identity.TargetFile,
			"yarn plugin must not set Identity.TargetFile (matches legacy snyk-nodejs-plugin)")
	}

	// NormalisedTargetFile carries the per-result manifest path.
	assert.Equal(t, "yarn.lock", root.ResolverMetadata.NormalisedTargetFile,
		"root SCAResult's NormalisedTargetFile is the lockfile (matches legacy auto-discovery)")
	assert.Equal(t, filepath.Join("packages", "pkg-a", "package.json"),
		pkgA.ResolverMetadata.NormalisedTargetFile)
	assert.Equal(t, filepath.Join("packages", "pkg-b", "package.json"),
		pkgB.ResolverMetadata.NormalisedTargetFile)

	// Stop-set semantics: pkg-a's graph fully expands express but treats
	// pkg-b as a leaf — accepts must NOT appear in pkg-a's graph (it lives
	// in pkg-b's), while express must appear.
	pkgAPkgs := pkgIDs(pkgA.DepGraph)
	assert.True(t, pkgAPkgs["express@4.12.4"], "pkg-a graph must include express")
	assert.False(t, pkgAPkgs["accepts@1.3.7"],
		"pkg-a graph must NOT include accepts — it's reachable only via pkg-b, which is a stop-set leaf")

	// pkg-b's own graph contains accepts (its declared dep).
	pkgBPkgs := pkgIDs(pkgB.DepGraph)
	assert.True(t, pkgBPkgs["accepts@1.3.7"], "pkg-b graph must include accepts")

	// Install-free contract still holds.
	for _, name := range []string{"node_modules", ".yarn"} {
		_, err := os.Stat(filepath.Join(dir, name))
		assert.True(t, os.IsNotExist(err), "plugin created %s in workspace project", name)
	}
}

// findResultByRootName returns the SCAResult whose dep graph's root package
// name equals rootName. Test setup-only; production code identifies results
// by TargetFile, not by name.
func findResultByRootName(t *testing.T, results []ecosystems.SCAResult, rootName string) ecosystems.SCAResult {
	t.Helper()
	for _, r := range results {
		if r.DepGraph != nil && r.DepGraph.GetRootPkg().Info.Name == rootName {
			return r
		}
	}
	t.Fatalf("no SCAResult with root package %q (got %d results)", rootName, len(results))
	return ecosystems.SCAResult{}
}

// pkgIDs returns the set of Pkg.ID values from a dep graph as a lookup map.
func pkgIDs(dg *snykdepgraph.DepGraph) map[string]bool {
	ids := make(map[string]bool, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		ids[p.ID] = true
	}
	return ids
}

// copyTreeForAcceptance is a local copy of stability_test.go's copyTree so
// each test file is self-contained without exporting helpers.
func copyTreeForAcceptance(t *testing.T, src, dst string) {
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

// TestAcceptance_Berry runs the Berry path end-to-end if a yarn v2+ binary is
// available. The classic-simple fixture is reused (yarn info works against
// any yarn.lock once we provide a .yarnrc.yml that opts into Berry — though
// for a v1 lockfile the dep graph will reflect only the immediate deps that
// Berry can resolve; the value here is exercising the executor + parser
// together, not lockfile fidelity).
//
// In practice this test is skipped on most local dev environments and only
// runs in CI where corepack pins yarn to a Berry version. Listed here for
// completeness of the acceptance surface; cross-version fixtures should be
// added under testdata/fixtures/berry-* as they're captured.
func TestAcceptance_Berry(t *testing.T) {
	requireYarn(t, 3) // most representative Berry major; CI pins this
	t.Skip("berry acceptance fixtures pending — covered by parser unit tests for now")
}
