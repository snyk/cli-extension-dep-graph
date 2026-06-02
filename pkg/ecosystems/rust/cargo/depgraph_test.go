package cargo

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDepGraph(t *testing.T) {
	tests := []struct {
		name     string
		out      *treeOutput
		wantRoot string
		wantPkgs []string
	}{
		{
			name: "root with no deps",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0": {},
				},
			},
			wantRoot: "my-app",
			wantPkgs: []string{"my-app@0.1.0"},
		},
		{
			name: "linear chain",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0":         {"serde@1.0.193": {}},
					"serde@1.0.193":        {"serde_derive@1.0.193": {}},
					"serde_derive@1.0.193": {},
				},
			},
			wantRoot: "my-app",
			wantPkgs: []string{"my-app@0.1.0", "serde@1.0.193", "serde_derive@1.0.193"},
		},
		{
			name: "diamond dependency (same crate reached by two paths)",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0": {"a@1.0.0": {}, "b@1.0.0": {}},
					"a@1.0.0":      {"shared@1.0.0": {}},
					"b@1.0.0":      {"shared@1.0.0": {}},
					"shared@1.0.0": {},
				},
			},
			wantRoot: "my-app",
			wantPkgs: []string{"my-app@0.1.0", "a@1.0.0", "b@1.0.0", "shared@1.0.0"},
		},
		{
			name: "cycle does not infinite-loop",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0": {"foo@1.0.0": {}},
					"foo@1.0.0":    {"bar@1.0.0": {}},
					"bar@1.0.0":    {"foo@1.0.0": {}},
				},
			},
			wantRoot: "my-app",
			wantPkgs: []string{"my-app@0.1.0", "foo@1.0.0", "bar@1.0.0"},
		},
		{
			name: "multiple versions of the same crate coexist as distinct nodes",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0":    {"rand@0.8.5": {}, "rand_core@0.7.0": {}},
					"rand@0.8.5":      {"rand_core@0.6.4": {}},
					"rand_core@0.6.4": {},
					"rand_core@0.7.0": {},
				},
			},
			wantRoot: "my-app",
			wantPkgs: []string{"my-app@0.1.0", "rand@0.8.5", "rand_core@0.6.4", "rand_core@0.7.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dg, err := buildDepGraph(tt.out)
			require.NoError(t, err)

			assert.Equal(t, tt.wantRoot, dg.GetRootPkg().Info.Name)
			assert.Equal(t, "cargo", dg.PkgManager.Name)

			gotPkgs := make([]string, 0, len(dg.Pkgs))
			for _, p := range dg.Pkgs {
				gotPkgs = append(gotPkgs, p.ID)
			}

			sort.Strings(gotPkgs)
			sort.Strings(tt.wantPkgs)
			assert.Equal(t, tt.wantPkgs, gotPkgs)
		})
	}
}
