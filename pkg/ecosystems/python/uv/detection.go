package uv

import (
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
)

// IsUvProject reports whether the given directory should be treated as a uv
// project. It performs a cheap filesystem check for uv lockfiles first, and
// only if one is found does it check the enableUvCLI feature flag in the
// configuration (which may trigger a network call on first access).
//
// Returns false when no uv lockfile is present or when the feature flag is
// not enabled.
func IsUvProject(dir, targetFile string, allProjects bool, config configuration.Configuration) bool {
	if !HasLockFile(dir, targetFile, allProjects, nil) {
		return false
	}
	return config.GetBool(workflow.FeatureFlagUvCLI)
}
