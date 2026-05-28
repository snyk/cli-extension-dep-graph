package bazel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

func Test_checkTargetLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		count   int
		options *ecosystems.SCAPluginOptions
		wantErr bool
	}{
		{
			name:    "nil options applies default ceiling, count below",
			count:   defaultMaxTargets - 1,
			options: nil,
			wantErr: false,
		},
		{
			name:    "nil options applies default ceiling, count above",
			count:   defaultMaxTargets + 1,
			options: nil,
			wantErr: true,
		},
		{
			name:    "unset MaxTargets applies default ceiling, count above",
			count:   defaultMaxTargets + 1,
			options: ecosystems.NewPluginOptions(),
			wantErr: true,
		},
		{
			name:    "explicit override honored, count below",
			count:   10,
			options: ecosystems.NewPluginOptions().WithBazelMaxTargets(50),
			wantErr: false,
		},
		{
			name:    "explicit override honored, count above",
			count:   51,
			options: ecosystems.NewPluginOptions().WithBazelMaxTargets(50),
			wantErr: true,
		},
		{
			name:    "explicit override honored, count at limit",
			count:   50,
			options: ecosystems.NewPluginOptions().WithBazelMaxTargets(50),
			wantErr: false,
		},
		{
			name:    "explicit zero disables ceiling",
			count:   1_000_000,
			options: ecosystems.NewPluginOptions().WithBazelMaxTargets(0),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkTargetLimit(tt.count, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "exceeds the safe limit")
				assert.Contains(t, err.Error(), "--bazel-max-targets")
				return
			}
			assert.NoError(t, err)
		})
	}
}
