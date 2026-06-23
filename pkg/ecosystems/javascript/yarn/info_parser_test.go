package yarn

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// TestParseYarnInfoOutput_Simple verifies parsing of a real, install-free
// `yarn info --all --recursive --json` capture (the same fixture used by
// nodejs-lockfile-parser's TS parser for parity).
func TestParseYarnInfoOutput_Simple(t *testing.T) {
	data, err := os.ReadFile("testdata/fixtures/berry-simple/info_output.txt")
	require.NoError(t, err)

	out, err := parseYarnInfoOutput(context.Background(), logger.Nop(), bytes.NewReader(data), nil)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Root workspace ("simple-tester-y2@workspace:.") declares one direct dep: accepts.
	assert.Equal(t, []string{"accepts@npm:1.3.7"}, out.ProdDeps)
	assert.Empty(t, out.DevDeps, "yarn info doesn't distinguish dev — all deps go in ProdDeps")
	assert.Empty(t, out.Workspaces, "fixture has only a root workspace; no members")

	// Forward edges populated as expected.
	require.Contains(t, out.Graph, "accepts@npm:1.3.7")
	assert.ElementsMatch(
		t,
		[]string{"mime-types@npm:2.1.31", "negotiator@npm:0.6.2"},
		setKeys(out.Graph["accepts@npm:1.3.7"]),
	)
	require.Contains(t, out.Graph, "mime-types@npm:2.1.31")
	assert.ElementsMatch(
		t,
		[]string{"mime-db@npm:1.48.0"},
		setKeys(out.Graph["mime-types@npm:2.1.31"]),
	)

	// Leaf packages exist in the graph as empty entries (no out-edges).
	require.Contains(t, out.Graph, "mime-db@npm:1.48.0")
	assert.Empty(t, out.Graph["mime-db@npm:1.48.0"])

	require.Contains(t, out.Graph, "negotiator@npm:0.6.2")
	assert.Empty(t, out.Graph["negotiator@npm:0.6.2"])
}

// TestParseYarnInfoOutput_DevirtualisesDependencyLocators verifies that peer-
// virtualised locators in the Dependencies array collapse to their underlying
// real locator, so multiple virtualisations of the same package become a
// single graph node.
func TestParseYarnInfoOutput_DevirtualisesDependencyLocators(t *testing.T) {
	//nolint:lll // NDJSON test inputs are intentionally single-line.
	ndjson := strings.Join([]string{
		`{"value":"root@workspace:.","children":{"Version":"0.0.0-use.local","Dependencies":[{"descriptor":"debug@npm:4.3.1","locator":"debug@virtual:abc123#npm:4.3.1"}]}}`,
		`{"value":"debug@npm:4.3.1","children":{"Version":"4.3.1","Dependencies":[{"descriptor":"ms@npm:1.0.0","locator":"ms@virtual:def456#npm:1.0.0"}]}}`,
		`{"value":"ms@npm:1.0.0","children":{"Version":"1.0.0"}}`,
	}, "\n")

	out, err := parseYarnInfoOutput(context.Background(), logger.Nop(), strings.NewReader(ndjson), nil)
	require.NoError(t, err)

	// Root → debug, with virtual stripped.
	assert.Equal(t, []string{"debug@npm:4.3.1"}, out.ProdDeps)

	// Cross-reference inside debug's deps also de-virtualised.
	assert.ElementsMatch(
		t,
		[]string{"ms@npm:1.0.0"},
		setKeys(out.Graph["debug@npm:4.3.1"]),
	)
}

// TestParseYarnInfoOutput_WorkspaceMembers verifies workspace members are
// populated with the right dir/name/version and added to the Graph so their
// own dep graphs can be built downstream.
func TestParseYarnInfoOutput_WorkspaceMembers(t *testing.T) {
	//nolint:lll // NDJSON test inputs are intentionally single-line.
	ndjson := strings.Join([]string{
		`{"value":"my-monorepo@workspace:.","children":{"Version":"1.0.0","Dependencies":[{"descriptor":"@my/logger@workspace:^","locator":"@my/logger@workspace:packages/logger"},{"descriptor":"axios@npm:^1","locator":"axios@npm:1.6.0"}]}}`,
		`{"value":"@my/logger@workspace:packages/logger","children":{"Version":"0.1.0","Dependencies":[{"descriptor":"chalk@npm:^5","locator":"chalk@npm:5.3.0"}]}}`,
		`{"value":"axios@npm:1.6.0","children":{"Version":"1.6.0"}}`,
		`{"value":"chalk@npm:5.3.0","children":{"Version":"5.3.0"}}`,
	}, "\n")

	out, err := parseYarnInfoOutput(context.Background(), logger.Nop(), strings.NewReader(ndjson), nil)
	require.NoError(t, err)

	// Root deps include both the workspace member and a regular package.
	assert.ElementsMatch(
		t,
		[]string{"@my/logger@workspace:packages/logger", "axios@npm:1.6.0"},
		out.ProdDeps,
	)

	// Workspace member registered with correct dir, name, version.
	require.Contains(t, out.Workspaces, "@my/logger@workspace:packages/logger")
	ws := out.Workspaces["@my/logger@workspace:packages/logger"]
	assert.Equal(t, "packages/logger", ws.Dir)
	assert.Equal(t, "@my/logger", ws.Name)
	assert.Equal(t, "0.1.0", ws.Version)

	// Workspace member's deps live in the Graph so its own dep graph can be built.
	require.Contains(t, out.Graph, "@my/logger@workspace:packages/logger")
	assert.ElementsMatch(
		t,
		[]string{"chalk@npm:5.3.0"},
		setKeys(out.Graph["@my/logger@workspace:packages/logger"]),
	)
}

// TestParseYarnInfoOutput_SkipsMalformedLines exercises the resilience path:
// a corrupt JSON line should be logged and skipped, not abort the whole parse.
func TestParseYarnInfoOutput_SkipsMalformedLines(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"value":"root@workspace:.","children":{"Dependencies":[{"descriptor":"debug@npm:4.3.1","locator":"debug@npm:4.3.1"}]}}`,
		`this is not json`,
		`{"value":"debug@npm:4.3.1","children":{"Version":"4.3.1"}}`,
	}, "\n")

	out, err := parseYarnInfoOutput(context.Background(), logger.Nop(), strings.NewReader(ndjson), nil)
	require.NoError(t, err)

	// The malformed line was skipped; valid lines still produced output.
	assert.Equal(t, []string{"debug@npm:4.3.1"}, out.ProdDeps)
	assert.Contains(t, out.Graph, "debug@npm:4.3.1")
}

func TestClassifyLocator(t *testing.T) {
	cases := []struct {
		in       string
		wantKind locatorKind
		wantDir  string
	}{
		{"name@workspace:.", locatorRoot, ""},
		{"@scope/name@workspace:.", locatorRoot, ""},
		{"name@workspace:packages/a", locatorWorkspace, "packages/a"},
		{"@scope/name@workspace:packages/x", locatorWorkspace, "packages/x"},
		{"name@npm:1.2.3", locatorPackage, ""},
		{"@scope/name@npm:1.2.3", locatorPackage, ""},
		{"name@file:./local", locatorPackage, ""},
		{"name@patch:base.tgz#patch.diff", locatorPackage, ""},
		{"orphan", locatorPackage, ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			k, d := classifyLocator(c.in)
			assert.Equal(t, c.wantKind, k)
			assert.Equal(t, c.wantDir, d)
		})
	}
}

func TestDevirtualise(t *testing.T) {
	cases := []struct{ in, want string }{
		{"debug@virtual:abc#npm:4.3.1", "debug@npm:4.3.1"},
		{"@scope/pkg@virtual:abc#npm:1.0.0", "@scope/pkg@npm:1.0.0"},
		{"debug@npm:4.3.1", "debug@npm:4.3.1"}, // idempotent on clean locators
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, devirtualise(c.in))
		})
	}
}

func TestSplitPkgID(t *testing.T) {
	cases := []struct {
		in          string
		wantName    string
		wantVersion string
	}{
		{"accepts@1.3.7", "accepts", "1.3.7"},
		{"@types/node@25.5.2", "@types/node", "25.5.2"},
		{"debug@npm:4.3.1", "debug", "4.3.1"},
		{"@scope/pkg@npm:1.2.3", "@scope/pkg", "1.2.3"},
		{"logger@workspace:packages/logger", "logger", "workspace:packages/logger"},
		{"orphan", "orphan", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			n, v := splitPkgID(c.in)
			assert.Equal(t, c.wantName, n)
			assert.Equal(t, c.wantVersion, v)
		})
	}
}

// setKeys returns the keys of a string-keyed set as a slice.
func setKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
