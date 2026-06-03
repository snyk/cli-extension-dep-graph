package bazel

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

func Test_newResolverFromOptions(t *testing.T) {
	t.Parallel()

	t.Run("nil options returns errNoBazelOptionFound", func(t *testing.T) {
		t.Parallel()
		_, err := newResolverFromOptions(t.TempDir(), nil)
		require.ErrorIs(t, err, errNoBazelOptionFound)
	})

	t.Run("no bazel flag set returns errNoBazelOptionFound", func(t *testing.T) {
		t.Parallel()
		_, err := newResolverFromOptions(t.TempDir(), ecosystems.NewPluginOptions())
		require.ErrorIs(t, err, errNoBazelOptionFound)
	})

	t.Run("both bazel flags set returns mutually-exclusive error", func(t *testing.T) {
		t.Parallel()
		opts := ecosystems.NewPluginOptions().WithBazelJvm(true).WithBazelGo(true)
		_, err := newResolverFromOptions(t.TempDir(), opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "mutually exclusive")
	})
}
