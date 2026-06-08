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
	assert.ElementsMatch(t,
		[]string{"mime-types@2.1.31", "negotiator@0.6.2"},
		setKeys(out.Graph["accepts@1.3.7"]),
	)

	require.Contains(t, out.Graph, "mime-types@2.1.31")
	assert.ElementsMatch(t,
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, resolveSpecifier(c.spec, resolved))
		})
	}
}

// TestParseYarnListOutput_WorkspaceMembers exercises the v1 workspace path:
// root package.json declares "workspaces"; each workspace's own package.json
// is read; workspace IDs are synthesized in "name@workspace:dir" form so
// depgraph.go can emit one graph per workspace.
func TestParseYarnListOutput_WorkspaceMembers(t *testing.T) {
	dir := t.TempDir()

	// Root manifest with two workspaces.
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"name": "monorepo",
		"version": "1.0.0",
		"workspaces": ["packages/*"],
		"dependencies": {"lodash": "^4"}
	}`)

	// Workspace A (named "@my/a"), depends on lodash.
	writeFile(t, filepath.Join(dir, "packages/a/package.json"), `{
		"name": "@my/a",
		"version": "0.1.0",
		"dependencies": {"lodash": "^4"}
	}`)

	// Workspace B (named "@my/b"), no deps.
	writeFile(t, filepath.Join(dir, "packages/b/package.json"), `{
		"name": "@my/b",
		"version": "0.2.0"
	}`)

	// Minimal yarn list output with the resolved lodash that ^4 should match.
	listJSON := `{"type":"tree","data":{"type":"list","trees":[
		{"name":"lodash@4.17.21","children":[],"hint":null,"color":null,"depth":0}
	]}}`

	rootPJ, err := readPackageJSON(dir)
	require.NoError(t, err)

	out, err := parseYarnListOutput(
		context.Background(), logger.Nop(),
		strings.NewReader(listJSON), rootPJ, dir,
	)
	require.NoError(t, err)

	// Root dep resolves through the universe.
	assert.Equal(t, []string{"lodash@4.17.21"}, out.ProdDeps)

	// Both workspaces registered with synthesized "name@workspace:dir" IDs.
	require.Contains(t, out.Workspaces, "@my/a@workspace:packages/a")
	require.Contains(t, out.Workspaces, "@my/b@workspace:packages/b")
	assert.Equal(t, "packages/a", out.Workspaces["@my/a@workspace:packages/a"].Dir)
	assert.Equal(t, "@my/a", out.Workspaces["@my/a@workspace:packages/a"].Name)
	assert.Equal(t, "0.1.0", out.Workspaces["@my/a@workspace:packages/a"].Version)

	// Workspace A's lodash dep resolved through the universe.
	assert.Contains(t, out.Graph, "@my/a@workspace:packages/a")
	assert.ElementsMatch(t,
		[]string{"lodash@4.17.21"},
		setKeys(out.Graph["@my/a@workspace:packages/a"]),
	)

	// Workspace B has no deps → empty entry, still present so its own dep
	// graph is emitted by depgraph.go.
	assert.Contains(t, out.Graph, "@my/b@workspace:packages/b")
	assert.Empty(t, out.Graph["@my/b@workspace:packages/b"])
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
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}
