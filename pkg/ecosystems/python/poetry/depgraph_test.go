//go:build !integration
// +build !integration

package poetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// readGolden loads a fixture from testdata/ and returns it as a string.
func readGolden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err, "reading fixture %s", name)
	return string(data)
}

func TestChildDepth(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{"├── foo bar", 1},
		{"└── foo bar", 1},
		{"│   └── foo 1.0", 2},
		{"    └── foo 1.0", 2},
		{"│   │   └── foo 1.0", 3},
		{"        └── foo 1.0", 3},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			assert.Equal(t, c.want, childDepth(c.line))
		})
	}
}

func TestParseTreeOutput_FlatTopLevel(t *testing.T) {
	got, err := parseTreeOutput(strings.NewReader(readGolden(t, "tree_simple.txt")))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "six", got[0].Name)
	assert.Equal(t, "1.17.0", got[0].Version)
	assert.Empty(t, got[0].Children)
}

func TestParseTreeOutput_V1WithDevDeps(t *testing.T) {
	got, err := parseTreeOutput(strings.NewReader(readGolden(t, "tree_v1_with_devdeps.txt")))
	require.NoError(t, err)
	// All three top-level entries are independent packages here (no
	// transitive nesting). Verifies dev-group goldens parse cleanly.
	names := make([]string, len(got))
	for i, n := range got {
		names[i] = n.Name
	}
	assert.ElementsMatch(t, []string{"isodd", "simple-enum", "six"}, names)
}

func TestParseTreeOutput_V2NestedGroups(t *testing.T) {
	got, err := parseTreeOutput(strings.NewReader(readGolden(t, "tree_v2_groups.txt")))
	require.NoError(t, err)
	// Locate flask and walk its children.
	var flask *treeNode
	for _, n := range got {
		if n.Name == "flask" {
			flask = n
			break
		}
	}
	require.NotNil(t, flask, "flask must appear as a top-level entry")
	require.Len(t, flask.Children, 5)

	// click should have a single child (colorama) per the fixture.
	var click *treeNode
	for _, c := range flask.Children {
		if c.Name == "click" {
			click = c
			break
		}
	}
	require.NotNil(t, click)
	require.Len(t, click.Children, 1)
	assert.Equal(t, "colorama", click.Children[0].Name)

	// jinja2 → markupsafe (depth 2 child)
	var jinja *treeNode
	for _, c := range flask.Children {
		if c.Name == "jinja2" {
			jinja = c
			break
		}
	}
	require.NotNil(t, jinja)
	require.Len(t, jinja.Children, 1)
	assert.Equal(t, "markupsafe", jinja.Children[0].Name)
}

func TestBuildDepGraph_ResolvesConstraintsToConcreteVersions(t *testing.T) {
	tree, err := parseTreeOutput(strings.NewReader(readGolden(t, "tree_v2_groups.txt")))
	require.NoError(t, err)

	dg, err := buildDepGraphFromTree(t.Context(), logger.Nop(),
		rootPkg{Name: "myapp", Version: "0.0.0"}, tree)
	require.NoError(t, err)
	require.NotNil(t, dg)

	// Every node carries the lockfile-pinned version (the top-level
	// entry's version), not the constraint that appeared on the edge.
	ids := map[string]bool{}
	for _, p := range dg.Pkgs {
		ids[p.ID] = true
	}
	assert.True(t, ids["flask@2.3.2"], "flask should be at concrete 2.3.2 (got: %v)", ids)
	assert.True(t, ids["click@8.1.7"])
	assert.True(t, ids["jinja2@3.1.2"])
	assert.True(t, ids["markupsafe@2.1.3"])
	assert.True(t, ids["colorama@0.4.6"])
}

func TestBuildDepGraph_BreaksCycles(t *testing.T) {
	tree, err := parseTreeOutput(strings.NewReader(readGolden(t, "tree_circular.txt")))
	require.NoError(t, err)

	dg, err := buildDepGraphFromTree(t.Context(), logger.Nop(),
		rootPkg{Name: "root", Version: "0.0.0"}, tree)
	require.NoError(t, err)
	require.NotNil(t, dg)

	// We must have at least one pruned leaf — confirms cycle detection
	// fired rather than blowing the stack.
	sawPruned := false
	for _, n := range dg.Graph.Nodes {
		if strings.HasSuffix(n.NodeID, ":pruned") {
			sawPruned = true
			break
		}
	}
	assert.True(t, sawPruned, "expected a pruned node for the circular dep")
}

func TestBuildDepGraph_DropsIgnoredPackages(t *testing.T) {
	tree, err := parseTreeOutput(strings.NewReader(readGolden(t, "tree_with_extras.txt")))
	require.NoError(t, err)

	dg, err := buildDepGraphFromTree(t.Context(), logger.Nop(),
		rootPkg{Name: "root", Version: "0.0.0"}, tree)
	require.NoError(t, err)

	for _, p := range dg.Pkgs {
		assert.NotEqual(t, "setuptools", p.Info.Name, "setuptools must be filtered out")
	}
}

func TestNormalizeName(t *testing.T) {
	assert.Equal(t, "my-pkg", normalizeName("My_Pkg"))
	assert.Equal(t, "django-rest-framework", normalizeName("Django_Rest_Framework"))
	assert.Equal(t, "flask", normalizeName("Flask"))
}

func TestIsConstraint(t *testing.T) {
	for _, in := range []string{">=1.0", "<2", "*", "^1.0", "~1.5", "(>=1,<2)", ""} {
		assert.True(t, isConstraint(in), "should classify %q as constraint", in)
	}
	for _, in := range []string{"1.0.0", "2.3.2", "1.17.0"} {
		assert.False(t, isConstraint(in), "should classify %q as concrete", in)
	}
}
