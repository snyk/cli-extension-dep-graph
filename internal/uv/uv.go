package uv

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

const UvLockFileName = "uv.lock"

// TODO(uv): this is copied from cli-extension-os-flows - should be exported from here and imported there.
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
