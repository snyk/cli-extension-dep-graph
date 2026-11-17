package childenv

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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

func TestEnvironReturnsExternalProgramFailedErrorWhenDirCannotBeResolved(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("PWD is not set on windows or plan9")
	}
	gone := filepath.Join(t.TempDir(), "gone")
	require.NoError(t, os.Mkdir(gone, 0o755))
	t.Chdir(gone)
	require.NoError(t, os.Remove(gone))
	if _, err := filepath.Abs("."); err == nil {
		t.Skip("platform resolves the working directory of a removed directory")
	}

	_, err := Environ("sub")

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, "SNYK-CLI-0039", snykErr.ErrorCode)
}
