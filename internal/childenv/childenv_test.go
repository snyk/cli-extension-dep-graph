package childenv

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvironRemovesSnykVariablesAndKeepsOthers(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "secret")
	t.Setenv("snyk_lower", "secret")
	t.Setenv("KEEP_ME", "1")

	env, err := Environ(t.TempDir())
	require.NoError(t, err)

	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		assert.False(t, strings.HasPrefix(strings.ToLower(name), snykPrefix), "unexpected entry %q", name)
	}
	assert.Contains(t, env, "KEEP_ME=1")
}
