package yarn

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// TestParseYarnListOutput_Simple exercises parsing of a captured
// `yarn list --depth=Infinity --json --frozen-lockfile` output paired with
// the project's package.json (root deps are derived from the manifest because
// yarn list does not emit a root-tree entry).
func TestParseYarnListOutput_Simple(t *testing.T) {
	fixtureDir := "testdata/fixtures/classic-simple"

	data, err := os.ReadFile(filepath.Join(fixtureDir, "list_output.txt"))
	require.NoError(t, err)

	pkgJSON, err := readPackageJSON(fixtureDir)
	require.NoError(t, err)

	out, err := parseYarnListOutput(context.Background(), logger.Nop(), bytes.NewReader(data), pkgJSON, fixtureDir)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Root has one declared dep: "accepts": "1.3.7" — exact match against resolved.
	assert.Equal(t, []string{"accepts@1.3.7"}, out.ProdDeps)
	assert.Empty(t, out.DevDeps)
	assert.Empty(t, out.Workspaces)

	// Semver disambiguation: "mime-types@~2.1.24" → resolved "mime-types@2.1.31".
	require.Contains(t, out.Graph, "accepts@1.3.7")
	assert.ElementsMatch(
		t,
		[]string{"mime-types@2.1.31", "negotiator@0.6.2"},
		setKeys(out.Graph["accepts@1.3.7"]),
	)

	require.Contains(t, out.Graph, "mime-types@2.1.31")
	assert.ElementsMatch(
		t,
		[]string{"mime-db@1.48.0"},
		setKeys(out.Graph["mime-types@2.1.31"]),
	)

	// Leaves have empty out-edges but ARE in the graph (resolved tree entry exists).
	assert.Contains(t, out.Graph, "mime-db@1.48.0")
	assert.Empty(t, out.Graph["mime-db@1.48.0"])
	assert.Contains(t, out.Graph, "negotiator@0.6.2")
}

// TestResolveSpecifier covers the semver matching surface that v1 needs to
// turn declared specifiers ("mime-types@~2.1.24") into resolved IDs.
func TestResolveSpecifier(t *testing.T) {
	resolved := []string{
		"mime-types@2.0.1",
		"mime-types@2.1.31",
		"lodash@4.17.21",
		"@scope/pkg@1.0.0",
		"@scope/pkg@2.0.0",
		// Sibling versions where lexicographic order disagrees with semver
		// order. Used by the "2.0.10 over 2.0.9" case below.
		"lex@2.0.9",
		"lex@2.0.10",
	}

	cases := []struct {
		name string
		spec string
		want string
	}{
		{"exact match", "lodash@4.17.21", "lodash@4.17.21"},
		{"caret picks highest in range", "mime-types@^2.0.0", "mime-types@2.1.31"},
		{"tilde picks highest in minor", "mime-types@~2.1.0", "mime-types@2.1.31"},
		{"tilde excludes minor bump", "mime-types@~2.0.0", "mime-types@2.0.1"},
		{"wildcard picks highest", "mime-types@*", "mime-types@2.1.31"},
		{"scoped package range", "@scope/pkg@^1", "@scope/pkg@1.0.0"},
		{"scoped package latest", "@scope/pkg@*", "@scope/pkg@2.0.0"},
		{"unmatched name", "missing@^1", ""},
		// Tag-like specifiers don't parse as semver constraints; we surface the
		// raw spec so the caller still has a graph node.
		{"tag returned verbatim", "lodash@latest", "lodash@latest"},
		// URL/git specifiers same fallback as tags.
		{"git url returned verbatim", "pkg@git+https://example/repo.git", "pkg@git+https://example/repo.git"},
		// Classic semver pitfall: a lexicographic comparison would pick "2.0.9"
		// over "2.0.10" because '9' > '1'. Parity with the existing TS test in
		// nodejs-lockfile-parser/test/jest/cli-parsers/cli-parser-utils.test.ts.
		{
			"semver picks 2.0.10 over 2.0.9 for ~2.0.0",
			"lex@~2.0.0", "lex@2.0.10",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, resolveSpecifier(c.spec, resolved, nil))
		})
	}
}

// TestResolveSpecifier_LockfileLookup covers the lockfile pre-pass that lets
// non-semver specifiers (URLs, git URLs, tarballs, npm: aliases) resolve to
// their lockfile-recorded versions. Without this path, real customer projects
// using any of these patterns would silently drop the dep.
func TestResolveSpecifier_LockfileLookup(t *testing.T) {
	resolved := []string{"body-parser@1.9.0", "lodash@4.17.21"}
	lock := map[string]string{
		"body-parser@https://example.com/body-parser-1.9.0.tar.gz": "body-parser@1.9.0",
		"body-parser@git+ssh://git@example.com/x.git#1.9.0":        "body-parser@1.9.0",
		"lodash@npm:lodash@^4.17.15":                               "lodash@4.17.21",
	}

	cases := []struct {
		name string
		spec string
		want string
	}{
		{
			"tarball URL resolves via lockfile",
			"body-parser@https://example.com/body-parser-1.9.0.tar.gz", "body-parser@1.9.0",
		},
		{
			"git+ssh URL resolves via lockfile",
			"body-parser@git+ssh://git@example.com/x.git#1.9.0", "body-parser@1.9.0",
		},
		{
			"npm: alias resolves via lockfile",
			"lodash@npm:lodash@^4.17.15", "lodash@4.17.21",
		},
		{
			"spec not in lockfile or universe falls through to raw",
			"body-parser@https://other.example/foo.tar.gz",
			"body-parser@https://other.example/foo.tar.gz",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, resolveSpecifier(c.spec, resolved, lock))
		})
	}
}

func TestParseYarnLockResolutions(t *testing.T) {
	data := []byte(`# THIS IS AN AUTOGENERATED FILE.

"body-parser@https://example.com/body-parser-1.9.0.tar.gz":
  version "1.9.0"
  resolved "https://example.com/body-parser-1.9.0.tar.gz"

bytes@1, bytes@1.0.0:
  version "1.0.0"
  resolved "..."

"lodash@npm:lodash@^4.17.15":
  version "4.17.21"

# trailing comment
`)
	got := parseYarnLockResolutions(data)
	want := map[string]string{
		"body-parser@https://example.com/body-parser-1.9.0.tar.gz": "body-parser@1.9.0",
		"bytes@1":                    "bytes@1.0.0",
		"bytes@1.0.0":                "bytes@1.0.0",
		"lodash@npm:lodash@^4.17.15": "lodash@4.17.21",
	}
	assert.Equal(t, want, got)
}

// TestParseYarnListOutput_SkipsWarningEnvelopes confirms the parser tolerates
// warning / info envelopes that real yarn emits before the tree (missing
// license, missing description, peer-dep mismatches). Real customer projects
// routinely trigger these — a previous version of this parser whole-buffer-
// decoded the output and broke the moment a single warning preceded the tree.
func TestParseYarnListOutput_SkipsWarningEnvelopes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"name": "no-license",
		"version": "0.0.1",
		"dependencies": {"debug": "^2"}
	}`)

	//nolint:lll // NDJSON test inputs are intentionally single-line.
	ndjson := strings.Join([]string{
		`{"type":"warning","data":"package.json: No license field"}`,
		`{"type":"warning","data":"no-license@0.0.1: No license field"}`,
		`{"type":"info","data":"Visit https://yarnpkg.com/en/docs/cli/list for documentation about this command."}`,
		`{"type":"tree","data":{"type":"list","trees":[{"name":"debug@2.6.9","children":[{"name":"ms@2.0.0","color":"dim","shadow":true}],"hint":null,"color":"bold","depth":0},{"name":"ms@2.0.0","children":[],"hint":null,"color":null,"depth":0}]}}`,
	}, "\n")

	pj, err := readPackageJSON(dir)
	require.NoError(t, err)

	out, err := parseYarnListOutput(
		context.Background(), logger.Nop(),
		strings.NewReader(ndjson), pj, dir,
	)
	require.NoError(t, err)

	assert.Equal(t, []string{"debug@2.6.9"}, out.ProdDeps)
	assert.Contains(t, out.Graph, "debug@2.6.9")
	assert.ElementsMatch(t, []string{"ms@2.0.0"}, setKeys(out.Graph["debug@2.6.9"]))
}

// TestParseYarnListOutput_SurfacesYarnError confirms that an error envelope
// from yarn (e.g. file: dep pointing at a missing path) is surfaced rather
// than silently producing an empty graph. The file-as-version fixture in
// nodejs-lockfile-parser exercises this path against real yarn.
func TestParseYarnListOutput_SurfacesYarnError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"x","version":"1.0.0"}`)

	ndjson := strings.Join([]string{
		`{"type":"warning","data":"package.json: No license field"}`,
		`{"type":"error","data":"Package \"shared\" refers to a non-existing file './missing'."}`,
	}, "\n")

	pj, err := readPackageJSON(dir)
	require.NoError(t, err)
	_, err = parseYarnListOutput(context.Background(), logger.Nop(), strings.NewReader(ndjson), pj, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-existing file")
}

// TestParseYarnListOutput_WorkspaceMembers exercises the v1 workspace path.
// Yarn list emits workspace packages as regular "name@version" tree entries
// (verified against the workspace-with-cross-ref fixture); we use those IDs
// directly rather than synthesizing alternatives, so cross-workspace edges
// like "pkg-a -> pkg-b@1.0.0" resolve naturally through the same universe.
//
// The parser identifies workspaces by reading the root package.json's
// `workspaces` field, then locating each workspace's "name@version" entry in
// the trees and flagging it. depgraph.go uses the flag to emit one dep graph
// per workspace and treat sibling workspaces as leaves in non-owner graphs.
func TestParseYarnListOutput_WorkspaceMembers(t *testing.T) {
	dir := t.TempDir()

	// Root manifest with two workspaces.
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"name": "monorepo",
		"version": "1.0.0",
		"workspaces": ["packages/*"],
		"dependencies": {"lodash": "^4"}
	}`)

	// Workspace A: depends on lodash AND on workspace B (cross-ref).
	writeFile(t, filepath.Join(dir, "packages/a/package.json"), `{
		"name": "@my/a",
		"version": "0.1.0",
		"dependencies": {"lodash": "^4", "@my/b": "0.2.0"}
	}`)

	// Workspace B: no deps.
	writeFile(t, filepath.Join(dir, "packages/b/package.json"), `{
		"name": "@my/b",
		"version": "0.2.0"
	}`)

	// Real yarn list emits the workspaces as tree entries too — @my/a has both
	// lodash and @my/b as children. We mock that exact shape here.
	//nolint:lll // NDJSON test inputs are intentionally single-line.
	listJSON := `{"type":"tree","data":{"type":"list","trees":[` +
		`{"name":"@my/a@0.1.0","children":[{"name":"lodash@^4","color":"dim","shadow":true},{"name":"@my/b@0.2.0","color":"dim","shadow":true}],"hint":null,"color":"bold","depth":0},` +
		`{"name":"@my/b@0.2.0","children":[],"hint":null,"color":null,"depth":0},` +
		`{"name":"lodash@4.17.21","children":[],"hint":null,"color":null,"depth":0}` +
		`]}}`

	rootPJ, err := readPackageJSON(dir)
	require.NoError(t, err)

	out, err := parseYarnListOutput(
		context.Background(), logger.Nop(),
		strings.NewReader(listJSON), rootPJ, dir,
	)
	require.NoError(t, err)

	// Root dep resolves through the universe.
	assert.Equal(t, []string{"lodash@4.17.21"}, out.ProdDeps)

	// Workspaces registered with their resolved "name@version" IDs (yarn's own
	// form), each carrying the dir for its package.json.
	require.Contains(t, out.Workspaces, "@my/a@0.1.0")
	require.Contains(t, out.Workspaces, "@my/b@0.2.0")
	assert.Equal(t, "packages/a", out.Workspaces["@my/a@0.1.0"].Dir)
	assert.Equal(t, "@my/a", out.Workspaces["@my/a@0.1.0"].Name)
	assert.Equal(t, "0.1.0", out.Workspaces["@my/a@0.1.0"].Version)

	// Workspace A's deps come from the yarn list tree — both lodash (resolved
	// via semver) and the cross-ref to @my/b (exact match on resolved ID).
	require.Contains(t, out.Graph, "@my/a@0.1.0")
	assert.ElementsMatch(
		t,
		[]string{"lodash@4.17.21", "@my/b@0.2.0"},
		setKeys(out.Graph["@my/a@0.1.0"]),
	)

	// Workspace B has no deps → empty entry.
	require.Contains(t, out.Graph, "@my/b@0.2.0")
	assert.Empty(t, out.Graph["@my/b@0.2.0"])
}

func TestSplitNameAndIdentifier(t *testing.T) {
	cases := []struct {
		in, wantName, wantID string
	}{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"name@~1.2.3", "name", "~1.2.3"},
		{"orphan", "", ""}, // no "@" → not a spec
		{"", "", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			n, id := splitNameAndIdentifier(c.in)
			assert.Equal(t, c.wantName, n)
			assert.Equal(t, c.wantID, id)
		})
	}
}

// writeFile writes content to path, creating parent dirs as needed.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
