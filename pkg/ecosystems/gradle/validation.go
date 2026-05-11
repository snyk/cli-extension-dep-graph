package gradle

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// ValidateOptions validates the provided options and returns an error if any are invalid.
// This should be called early in the process to fail fast on configuration errors.
// The dir parameter is used to resolve and validate relative init script paths.
func ValidateOptions(dir string, options *ecosystems.SCAPluginOptions) error {
	if options == nil {
		return nil // No options to validate
	}

	// Validate Gradle configuration matching regex if provided
	if options.Gradle.ConfigurationMatching != "" {
		if _, err := regexp.Compile(options.Gradle.ConfigurationMatching); err != nil {
			return fmt.Errorf("invalid --configuration-matching regex pattern '%s': %w", options.Gradle.ConfigurationMatching, err)
		}
	}

	// Validate user init script if provided
	if userInitScript := options.Gradle.InitScript; userInitScript != "" {
		if err := validateInitScript(dir, userInitScript); err != nil {
			return err
		}
	}

	// Add validation for other options as needed in the future

	return nil
}

// validateInitScript validates an init script path (absolute or relative).
func validateInitScript(projectDir, initPath string) error {
	// Basic sanity checks
	if strings.TrimSpace(initPath) == "" {
		return fmt.Errorf("user init script path is empty")
	}

	// Resolve to absolute path for validation
	resolvedPath := initPath
	if !filepath.IsAbs(initPath) {
		resolvedPath = filepath.Join(projectDir, initPath)
	}

	// Validate that the file exists and is not a directory
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return fmt.Errorf("user init script not found: %s: %w", initPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("user init script is a directory, not a file: %s", initPath)
	}

	return nil
}
