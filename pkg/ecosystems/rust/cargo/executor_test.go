package cargo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildTreeArgs(t *testing.T) {
	tests := []struct {
		name         string
		opts         cargoTreeOpts
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "defaults",
			opts:         cargoTreeOpts{},
			wantContains: []string{"tree", "--locked", "--all-features", "--target=all", "--edges=normal,build", "--prefix=depth", "--no-dedupe", "--format={p}"},
			wantAbsent:   []string{"-p", "--edges=normal,build,dev"},
		},
		{
			name:         "include dev",
			opts:         cargoTreeOpts{IncludeDev: true},
			wantContains: []string{"--edges=normal,build,dev"},
			wantAbsent:   []string{"--edges=normal,build "}, // not the dev-less variant (trailing space marker for token boundary)
		},
		{
			name:         "allow out of sync drops --locked",
			opts:         cargoTreeOpts{AllowOutOfSync: true},
			wantContains: []string{"tree", "--all-features"},
			wantAbsent:   []string{"--locked"},
		},
		{
			name:         "scope to package",
			opts:         cargoTreeOpts{Pkg: "my-member"},
			wantContains: []string{"-p", "my-member"},
		},
		{
			name:         "all options combined",
			opts:         cargoTreeOpts{IncludeDev: true, AllowOutOfSync: true, Pkg: "x"},
			wantContains: []string{"--edges=normal,build,dev", "-p", "x"},
			wantAbsent:   []string{"--locked"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildTreeArgs(tt.opts)
			joined := " " + joinArgs(args) + " "

			for _, want := range tt.wantContains {
				assert.Contains(t, joined, " "+want+" ", "args should contain %q: got %v", want, args)
			}

			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, joined, " "+absent+" ", "args should NOT contain %q: got %v", absent, args)
			}
		})
	}
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
