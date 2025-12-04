package uv

import (
	"fmt"
	"path/filepath"
)

// normaliseTargetFile converts an absolute target file path to a relative path.
// It resolves symlinks to handle cases like /tmp -> /private/tmp on macOS.
// Returns the original path if it's already relative or empty.
func normaliseTargetFile(inputDir, targetFile string) (string, error) {
	if targetFile == "" || !filepath.IsAbs(targetFile) {
		return targetFile, nil
	}

	resolvedTarget, err := filepath.EvalSymlinks(targetFile)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target file path: %w", err)
	}

	resolvedInputDir, err := filepath.EvalSymlinks(inputDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve input directory path: %w", err)
	}

	absInputDir, err := filepath.Abs(resolvedInputDir)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute input directory: %w", err)
	}

	relPath, err := filepath.Rel(absInputDir, resolvedTarget)
	if err != nil {
		return "", fmt.Errorf("failed to compute relative path: %w", err)
	}

	return relPath, nil
}
