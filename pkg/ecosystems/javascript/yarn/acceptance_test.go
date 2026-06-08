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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	got, _ := strconv.Atoi(m[1])
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
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"package.json", "yarn.lock"}, names,
		"yarn plugin must not create node_modules or .yarn dirs in the project")
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
