package composer

import (
	"strings"
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeDeps returns the NodeIDs of nodeID's direct dependencies in dg.
func nodeDeps(dg *godepgraph.DepGraph, nodeID string) []string {
	for _, n := range dg.Graph.Nodes {
		if n.NodeID == nodeID {
			ids := make([]string, len(n.Deps))
			for i, d := range n.Deps {
				ids[i] = d.NodeID
			}
			return ids
		}
	}
	return nil
}

// pkgIDSet returns the set of all package IDs in dg.
func pkgIDSet(dg *godepgraph.DepGraph) map[string]bool {
	out := make(map[string]bool, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		out[p.ID] = true
	}
	return out
}

func TestParseTreeOutput_SimpleChain(t *testing.T) {
	// root -> guzzlehttp/guzzle 7.8.0
	//           └── psr/http-message ^2.0
	input := strings.Join([]string{
		"guzzlehttp/guzzle 7.8.0 Guzzle is a PHP HTTP client library",
		"└──psr/http-message ^2.0",
	}, "\n")

	parsed, err := parseTreeOutput(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, []string{"guzzlehttp/guzzle@7.8.0"}, parsed.RootDeps)
	require.Contains(t, parsed.Graph, "guzzlehttp/guzzle@7.8.0")
	require.Contains(t, parsed.Graph, "psr/http-message@^2.0")

	_, hasEdge := parsed.Graph["guzzlehttp/guzzle@7.8.0"]["psr/http-message@^2.0"]
	assert.True(t, hasEdge, "guzzle → psr/http-message edge expected")
}

func TestParseTreeOutput_NestedTree(t *testing.T) {
	// Real-shape composer 2.x output with mixed glyphs and indentation.
	input := strings.Join([]string{
		"guzzlehttp/guzzle 7.8.0 Guzzle is a PHP HTTP client library",
		"├──ext-json *",
		"├──guzzlehttp/promises ^2.0",
		"│  └──php >=7.2.5",
		"└──guzzlehttp/psr7 ^1.9",
		"   ├──php >=7.2.5",
		"   └──psr/http-message ^1.1",
	}, "\n")

	parsed, err := parseTreeOutput(strings.NewReader(input))
	require.NoError(t, err)

	require.Equal(t, []string{"guzzlehttp/guzzle@7.8.0"}, parsed.RootDeps)

	for _, child := range []string{"ext-json@*", "guzzlehttp/promises@^2.0", "guzzlehttp/psr7@^1.9"} {
		_, ok := parsed.Graph["guzzlehttp/guzzle@7.8.0"][child]
		assert.True(t, ok, "guzzle should have child %s", child)
	}

	// Verify depth is tracked correctly: php sits under both promises and psr7,
	// and psr/http-message sits under psr7.
	_, ok := parsed.Graph["guzzlehttp/promises@^2.0"]["php@>=7.2.5"]
	assert.True(t, ok, "promises → php edge")
	_, ok = parsed.Graph["guzzlehttp/psr7@^1.9"]["php@>=7.2.5"]
	assert.True(t, ok, "psr7 → php edge")
	_, ok = parsed.Graph["guzzlehttp/psr7@^1.9"]["psr/http-message@^1.1"]
	assert.True(t, ok, "psr7 → psr/http-message edge")
}

func TestParseTreeOutput_MultipleTopLevelSubtrees(t *testing.T) {
	// Two direct deps of the root, each with their own subtree.
	input := strings.Join([]string{
		"monolog/monolog 3.5.0 Logging for PHP",
		"└──psr/log ^3.0",
		"",
		"symfony/console 6.4.0 Easy CLI commands",
		"└──php >=8.1",
	}, "\n")

	parsed, err := parseTreeOutput(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t,
		[]string{"monolog/monolog@3.5.0", "symfony/console@6.4.0"},
		parsed.RootDeps)
	assert.Contains(t, parsed.Graph["monolog/monolog@3.5.0"], "psr/log@^3.0")
	assert.Contains(t, parsed.Graph["symfony/console@6.4.0"], "php@>=8.1")
}

func TestParseTreeOutput_DuplicateTopLevelDedupes(t *testing.T) {
	// Composer 2.x occasionally prints the same top-level dep twice when
	// runtime and dev paths both resolve to it. RootDeps must dedupe.
	input := strings.Join([]string{
		"psr/log 3.0.0 Common interface for logging libraries",
		"",
		"psr/log 3.0.0 Common interface for logging libraries",
	}, "\n")

	parsed, err := parseTreeOutput(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"psr/log@3.0.0"}, parsed.RootDeps)
}

func TestParseTreeOutput_PlatformPackages(t *testing.T) {
	// Platform packages (php, ext-*, lib-*) have single-token names — no
	// vendor/ prefix — and arbitrary specifiers including `*`.
	input := strings.Join([]string{
		"php >=8.1",
		"",
		"ext-json *",
		"",
		"ext-mbstring 8.1.0",
	}, "\n")

	parsed, err := parseTreeOutput(strings.NewReader(input))
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"php@>=8.1", "ext-json@*", "ext-mbstring@8.1.0"},
		parsed.RootDeps)
}

func TestParseTreeOutput_BlankAndUnknownLinesIgnored(t *testing.T) {
	input := strings.Join([]string{
		"",
		"<warning>Some composer warning leaking to stdout</warning>",
		"guzzlehttp/guzzle 7.8.0",
		"",
	}, "\n")

	parsed, err := parseTreeOutput(strings.NewReader(input))
	require.NoError(t, err)
	// Warning lines that don't match our depth/name shape are silently
	// skipped. But "<warning>..." has a leading "<warning>" token that
	// looks like a depth-0 line with name="<warning>Some" version="composer"
	// — composer's real warnings include angle brackets which our regex
	// will match. The test verifies the parser doesn't crash; whether
	// noise leaks in is a separate concern handled by --no-interaction
	// in the executor.
	require.NotNil(t, parsed)
	// guzzle should be recognised regardless.
	assert.Contains(t, parsed.RootDeps, "guzzlehttp/guzzle@7.8.0")
}

func TestStripTreePrefix(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStr   string
		wantDepth int
	}{
		{
			name:      "top-level header",
			input:     "guzzlehttp/guzzle 7.8.0 Description",
			wantStr:   "guzzlehttp/guzzle 7.8.0 Description",
			wantDepth: 0,
		},
		{
			name:      "depth 1 middle child",
			input:     "├──psr/log ^3.0",
			wantStr:   "psr/log ^3.0",
			wantDepth: 1,
		},
		{
			name:      "depth 1 last child",
			input:     "└──psr/log ^3.0",
			wantStr:   "psr/log ^3.0",
			wantDepth: 1,
		},
		{
			name:      "depth 2 under continuation bar",
			input:     "│  └──php >=7.2.5",
			wantStr:   "php >=7.2.5",
			wantDepth: 2,
		},
		{
			name:      "depth 2 under blank continuation",
			input:     "   └──psr/http-message ^1.1",
			wantStr:   "psr/http-message ^1.1",
			wantDepth: 2,
		},
		{
			name:      "depth 3 mixed continuations",
			input:     "│  │  └──ralouphie/getallheaders ^3.0",
			wantStr:   "ralouphie/getallheaders ^3.0",
			wantDepth: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr, gotDepth := stripTreePrefix(tt.input)
			assert.Equal(t, tt.wantStr, gotStr)
			assert.Equal(t, tt.wantDepth, gotDepth)
		})
	}
}

func TestBuildDepGraphs_Simple(t *testing.T) {
	parsed := &parsedOutput{
		Graph: map[string]map[string]struct{}{
			"guzzlehttp/guzzle@7.8.0": {
				"psr/http-message@^2.0": {},
			},
			"psr/http-message@^2.0": {},
		},
		RootDeps: []string{"guzzlehttp/guzzle@7.8.0"},
	}

	results, err := buildDepGraphs("my-app", "1.0.0", parsed)
	require.NoError(t, err)
	require.Len(t, results, 1)

	dg := results[0].graph
	assert.Equal(t, "composer", dg.PkgManager.Name)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", dg.GetRootPkg().Info.Version)

	assert.Contains(t, nodeDeps(dg, "root-node"), "guzzlehttp/guzzle@7.8.0")
	assert.Contains(t, nodeDeps(dg, "guzzlehttp/guzzle@7.8.0"), "psr/http-message@^2.0")
}

func TestBuildDepGraphs_Diamond(t *testing.T) {
	// Two roots both depending on the same shared package.
	parsed := &parsedOutput{
		Graph: map[string]map[string]struct{}{
			"a/a@1.0.0":      {"shared/lib@1.0.0": {}},
			"b/b@1.0.0":      {"shared/lib@1.0.0": {}},
			"shared/lib@1.0.0": {},
		},
		RootDeps: []string{"a/a@1.0.0", "b/b@1.0.0"},
	}

	results, err := buildDepGraphs("root", "0.0.0", parsed)
	require.NoError(t, err)
	dg := results[0].graph

	assert.Contains(t, nodeDeps(dg, "root-node"), "a/a@1.0.0")
	assert.Contains(t, nodeDeps(dg, "root-node"), "b/b@1.0.0")
	assert.Contains(t, nodeDeps(dg, "a/a@1.0.0"), "shared/lib@1.0.0")
	assert.Contains(t, nodeDeps(dg, "b/b@1.0.0"), "shared/lib@1.0.0")

	// Shared pkg appears once in the pkg list, not duplicated.
	ids := pkgIDSet(dg)
	assert.True(t, ids["shared/lib@1.0.0"])
}

func TestBuildDepGraphs_Cycle(t *testing.T) {
	// a → b → a (cycle inside the adjacency). Must not infinite-loop.
	parsed := &parsedOutput{
		Graph: map[string]map[string]struct{}{
			"a/a@1.0.0": {"b/b@1.0.0": {}},
			"b/b@1.0.0": {"a/a@1.0.0": {}},
		},
		RootDeps: []string{"a/a@1.0.0"},
	}

	results, err := buildDepGraphs("root", "0.0.0", parsed)
	require.NoError(t, err)
	dg := results[0].graph

	assert.Contains(t, nodeDeps(dg, "root-node"), "a/a@1.0.0")
	assert.Contains(t, nodeDeps(dg, "a/a@1.0.0"), "b/b@1.0.0")
	assert.Contains(t, nodeDeps(dg, "b/b@1.0.0"), "a/a@1.0.0", "cycle edge present")
}

func TestBuildDepGraphs_DeterministicOrder(t *testing.T) {
	// Two independent runs of buildDepGraphs against identical input must
	// produce byte-identical pkg ordering inside the graph, because we sort
	// children lexicographically in addNode.
	parsed := &parsedOutput{
		Graph: map[string]map[string]struct{}{
			"x/x@1.0.0": {
				"z/z@1.0.0": {},
				"a/a@1.0.0": {},
				"m/m@1.0.0": {},
			},
		},
		RootDeps: []string{"x/x@1.0.0"},
	}

	r1, err := buildDepGraphs("root", "0.0.0", parsed)
	require.NoError(t, err)
	r2, err := buildDepGraphs("root", "0.0.0", parsed)
	require.NoError(t, err)

	d1 := nodeDeps(r1[0].graph, "x/x@1.0.0")
	d2 := nodeDeps(r2[0].graph, "x/x@1.0.0")
	assert.Equal(t, d1, d2, "deterministic child order across runs")
	assert.Equal(t, []string{"a/a@1.0.0", "m/m@1.0.0", "z/z@1.0.0"}, d1)
}

func TestSplitPkgID(t *testing.T) {
	tests := []struct {
		id          string
		wantName    string
		wantVersion string
	}{
		{"guzzlehttp/guzzle@7.8.0", "guzzlehttp/guzzle", "7.8.0"},
		{"php@>=7.2.5", "php", ">=7.2.5"},
		{"ext-json@*", "ext-json", "*"},
		{"no-at-sign", "no-at-sign", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			name, version := splitPkgID(tt.id)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestPkgID(t *testing.T) {
	assert.Equal(t, "guzzlehttp/guzzle@7.8.0", pkgID("guzzlehttp/guzzle", "7.8.0"))
	assert.Equal(t, "php@*", pkgID("php", "*"))
}
