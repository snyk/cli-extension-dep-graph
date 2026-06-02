package cargo

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTree(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantRoot     string
		wantEdges    map[string][]string
		wantErr      bool
		wantErrSubst string
	}{
		{
			name: "single root with no deps",
			input: `0my-app v0.1.0
`,
			wantRoot:  "my-app@0.1.0",
			wantEdges: map[string][]string{"my-app@0.1.0": {}},
		},
		{
			name: "linear chain",
			input: `0my-app v0.1.0
1serde v1.0.193
2serde_derive v1.0.193 (proc-macro)
`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0":         {"serde@1.0.193"},
				"serde@1.0.193":        {"serde_derive@1.0.193"},
				"serde_derive@1.0.193": {},
			},
		},
		{
			name: "branching tree with siblings at depth 1",
			input: `0my-app v0.1.0
1serde v1.0.193
1tokio v1.35.0
2pin-project-lite v0.2.13
`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0":            {"serde@1.0.193", "tokio@1.35.0"},
				"serde@1.0.193":           {},
				"tokio@1.35.0":            {"pin-project-lite@0.2.13"},
				"pin-project-lite@0.2.13": {},
			},
		},
		{
			name: "multiple versions of the same crate coexist",
			input: `0my-app v0.1.0
1rand v0.8.5
2rand_core v0.6.4
1rand_core v0.7.0
`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0":    {"rand@0.8.5", "rand_core@0.7.0"},
				"rand@0.8.5":      {"rand_core@0.6.4"},
				"rand_core@0.6.4": {},
				"rand_core@0.7.0": {},
			},
		},
		{
			name: "cycle marker (*) is treated as a leaf",
			input: `0my-app v0.1.0
1foo v1.0.0
2bar v1.0.0
3foo v1.0.0 (*)
`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0": {"foo@1.0.0"},
				"foo@1.0.0":    {"bar@1.0.0"},
				"bar@1.0.0":    {"foo@1.0.0"},
			},
		},
		{
			name: "path source annotation is ignored for ID purposes",
			input: `0my-app v0.1.0 (/abs/path/to/my-app)
1my-lib v0.1.0 (/abs/path/to/my-lib)
`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0": {"my-lib@0.1.0"},
				"my-lib@0.1.0": {},
			},
		},
		{
			name: "blank lines are skipped",
			input: `0my-app v0.1.0

1serde v1.0.193

`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0":  {"serde@1.0.193"},
				"serde@1.0.193": {},
			},
		},
		{
			name: "unrecognized lines are skipped",
			input: `0my-app v0.1.0
[build-dependencies]
1cc v1.0.83
`,
			wantRoot: "my-app@0.1.0",
			wantEdges: map[string][]string{
				"my-app@0.1.0": {"cc@1.0.83"},
				"cc@1.0.83":    {},
			},
		},
		{
			name:         "empty input is an error",
			input:        "",
			wantErr:      true,
			wantErrSubst: "no root package found",
		},
		{
			name:         "child node before any root is an error",
			input:        "1orphan v0.1.0\n",
			wantErr:      true,
			wantErrSubst: "no parent in scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := parseTree(context.Background(), nil, strings.NewReader(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubst)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantRoot, out.RootID)
			assert.Equal(t, len(tt.wantEdges), len(out.Graph), "graph node count mismatch")

			for parent, wantChildren := range tt.wantEdges {
				children, ok := out.Graph[parent]
				require.True(t, ok, "expected node %q in graph", parent)

				gotChildren := make([]string, 0, len(children))
				for c := range children {
					gotChildren = append(gotChildren, c)
				}

				assert.ElementsMatch(t, wantChildren, gotChildren, "children of %s", parent)
			}
		})
	}
}

func TestSplitPkgID(t *testing.T) {
	tests := []struct {
		id          string
		wantName    string
		wantVersion string
	}{
		{"serde@1.0.193", "serde", "1.0.193"},
		{"proc-macro2@1.0.70", "proc-macro2", "1.0.70"},
		{"rand_core@0.6.4", "rand_core", "0.6.4"},
		{"my-app@0.1.0-alpha.1", "my-app", "0.1.0-alpha.1"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			name, version := splitPkgID(tt.id)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}
