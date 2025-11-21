package uv

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

const (
	UvLockFileName          = "uv.lock"
	RequirementsTxtFileName = "requirements.txt"
	PyprojectTomlFileName   = "pyproject.toml"
)

// This is copied from cli-extension-os-flows. We could export from here via GAF config and re-use if this duplication
// becomes a problem, but this duplication is only temporary.
func HasUvLockFile(dir string, logger *zerolog.Logger) bool {
	uvLockPath := filepath.Join(dir, UvLockFileName)
	_, err := os.Stat(uvLockPath)
	if err == nil {
		return true
	}

	if !errors.Is(err, os.ErrNotExist) && logger != nil {
		logger.Debug().
			Err(err).
			Str("path", uvLockPath).
			Msg("Error checking for uv.lock file")
	}

	return false
}
