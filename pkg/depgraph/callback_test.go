package depgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
)

func TestShouldUseOrchestratorResolution(t *testing.T) {
	t.Parallel()

	t.Run("returns true when unified test API feature flag is enabled", func(t *testing.T) {
		t.Parallel()
		config := configuration.New()
		config.Set(workflow.FeatureFlagUseUnifiedTestAPIForOSCliTest, true)

		assert.True(t, shouldUseOrchestratorResolution(config))
	})

	t.Run("returns false when unified test API feature flag is disabled", func(t *testing.T) {
		t.Parallel()
		config := configuration.New()
		config.Set(workflow.FeatureFlagUseUnifiedTestAPIForOSCliTest, false)

		assert.False(t, shouldUseOrchestratorResolution(config))
	})

	t.Run("returns false when unified test API feature flag is not set", func(t *testing.T) {
		t.Parallel()
		config := configuration.New()

		assert.False(t, shouldUseOrchestratorResolution(config))
	})
}

func TestShouldUseSBOMResolution(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns false when uv feature flag is disabled", func(t *testing.T) {
		t.Parallel()
		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, false)

		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns false when uv feature flag is not set", func(t *testing.T) {
		t.Parallel()
		config := configuration.New()

		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns false when uv feature flag is enabled but no uv.lock exists", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)

		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns true when uv feature flag is enabled and uv.lock exists", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createUvLockFile(t, dir)

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)

		assert.True(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns true when uv feature flag is enabled and uv.lock is targeted via file flag", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		subdir := filepath.Join(dir, "sub")
		createUvLockFile(t, subdir)

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)
		config.Set(workflow.FlagFile, "sub/uv.lock")

		assert.True(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns false when uv feature flag is enabled and file flag targets a non-uv file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)
		config.Set(workflow.FlagFile, "pom.xml")

		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns true with all-projects when uv.lock exists in subdirectory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createUvLockFile(t, filepath.Join(dir, "project1"))

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)
		config.Set(workflow.FlagAllProjects, true)

		assert.True(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("returns false with all-projects when no uv.lock exists anywhere", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)
		config.Set(workflow.FlagAllProjects, true)

		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})
}

func TestCallbackRouting(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("orchestrator takes priority over SBOM when both flags are set", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createUvLockFile(t, dir)

		config := configuration.New()
		config.Set(workflow.FeatureFlagUseUnifiedTestAPIForOSCliTest, true)
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)

		assert.True(t, shouldUseOrchestratorResolution(config),
			"orchestrator should be selected")
		assert.True(t, shouldUseSBOMResolution(config, &nopLogger),
			"SBOM would also match, but orchestrator has priority")
	})

	t.Run("SBOM resolution selected when only uv flag is set with lockfile", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createUvLockFile(t, dir)

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)

		assert.False(t, shouldUseOrchestratorResolution(config))
		assert.True(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("legacy fallback when no feature flags are set", func(t *testing.T) {
		t.Parallel()
		config := configuration.New()

		assert.False(t, shouldUseOrchestratorResolution(config))
		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})

	t.Run("legacy fallback when uv flag is set but no lockfile exists", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		config := configuration.New()
		config.Set(workflow.FeatureFlagUvCLI, true)
		config.Set(configuration.INPUT_DIRECTORY, dir)

		assert.False(t, shouldUseOrchestratorResolution(config))
		assert.False(t, shouldUseSBOMResolution(config, &nopLogger))
	})
}

func createUvLockFile(t *testing.T, dir string) {
	t.Helper()
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		t.Fatalf("failed to create directory %s: %v", dir, err)
	}
	err = os.WriteFile(filepath.Join(dir, "uv.lock"), []byte("# test lockfile"), 0o600)
	if err != nil {
		t.Fatalf("failed to create uv.lock: %v", err)
	}
}
