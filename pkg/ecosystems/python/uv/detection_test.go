package uv_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/uv"
)

const featureFlagUvCLI = "internal_snyk_cli_uv_enabled"

func TestIsUvProject(t *testing.T) {
	t.Parallel()

	t.Run("returns true when lockfile exists and FF is enabled", func(t *testing.T) {
		t.Parallel()
		dir := createUvLock(t)
		cfg := configuration.New()
		cfg.Set(featureFlagUvCLI, true)

		assert.True(t, uv.IsUvProject(dir, "", false, cfg))
	})

	t.Run("returns false when lockfile exists but FF is disabled", func(t *testing.T) {
		t.Parallel()
		dir := createUvLock(t)
		cfg := configuration.New()
		cfg.Set(featureFlagUvCLI, false)

		assert.False(t, uv.IsUvProject(dir, "", false, cfg))
	})

	t.Run("returns false when no lockfile exists even with FF enabled", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfg := configuration.New()
		cfg.Set(featureFlagUvCLI, true)

		assert.False(t, uv.IsUvProject(dir, "", false, cfg))
	})
}

func createUvLock(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uv.lock"), []byte("# test"), 0o600))
	return dir
}
