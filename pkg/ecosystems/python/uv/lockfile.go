//nolint:goconst // Some repeat strings for logging labels. Silencing the linter in favor of repetition.
package uv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

// ExcludedLockFileDirs is a list of directories that are excluded from the uv.lock file search.
var ExcludedLockFileDirs = map[string]bool{
	"node_modules": true,
	".build":       true,
}

// HasLockFile checks if the specified directory contains a uv.lock file or the target file if provided.
// If allProjects is true, the function will check if the directory contains a uv.lock file recursively.
// Otherwise, it will only check if the directory contains a uv.lock file.
func HasLockFile(dir, targetFile string, allProjects bool, logger *zerolog.Logger) bool {
	if allProjects {
		return HasLockFileRecursive(dir, logger)
	}
	return HasLockFileSingle(dir, targetFile, logger)
}

// HasLockFileSingle checks if the specified directory contains a uv.lock file.
// If targetFile is provided and is a uv.lock file (by name), it will be checked;
// otherwise, the function looks for uv.lock in the directory.
func HasLockFileSingle(dir, targetFile string, logger *zerolog.Logger) bool {
	var uvLockPath string
	if targetFile != "" && filepath.Base(targetFile) == LockFileName {
		if filepath.IsAbs(targetFile) {
			uvLockPath = targetFile
		} else {
			uvLockPath = filepath.Join(dir, targetFile)
		}
	} else {
		uvLockPath = filepath.Join(dir, LockFileName)
	}

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

// HasLockFileRecursive checks if any directory within dir (including dir itself)
// contains a uv.lock file, skipping directories in ExcludedLockFileDirs.
func HasLockFileRecursive(dir string, logger *zerolog.Logger) bool {
	found := false
	fpErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if logger != nil {
				logger.Debug().
					Err(err).
					Str("path", path).
					Msg("Error accessing path during uv.lock search")
			}
			return nil
		}

		if d.IsDir() {
			dirName := d.Name()
			if ExcludedLockFileDirs[dirName] {
				if logger != nil {
					logger.Debug().
						Str("path", path).
						Msg("Skipping excluded directory during uv.lock search")
				}
				return fs.SkipDir
			}
			return nil
		}

		if d.Name() == LockFileName {
			found = true
			return fs.SkipAll
		}

		return nil
	})

	if fpErr != nil && logger != nil {
		logger.Debug().
			Err(fpErr).
			Str("path", dir).
			Msg("Error checking for uv.lock file")
	}

	return found
}
