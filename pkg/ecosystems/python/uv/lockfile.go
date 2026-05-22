package uv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

const logKeyPath = "path"

// ExcludedUVLockFileDirs is a list of directories that are excluded from the uv.lock file search.
var ExcludedUVLockFileDirs = map[string]bool{
	"node_modules": true,
	".build":       true,
}

// HasUvLockFile checks if the specified directory contains a uv.lock file or the target file if provided.
// If searchDeep is true, the function will check if the directory contains a uv.lock file recursively.
// Otherwise, it will only check if the directory contains a uv.lock file.
func HasUvLockFile(dir, targetFile string, searchDeep bool, logger *zerolog.Logger) bool {
	if searchDeep {
		return hasUvLockFileRecursive(dir, logger)
	}
	return hasUvLockFileSingle(dir, targetFile, logger)
}

// HasUvLockFileSingle checks if the specified directory contains a uv.lock file.
// If targetFile is provided and is a uv.lock file (by name), it will be checked;
// otherwise, the function looks for uv.lock in the directory.
func hasUvLockFileSingle(dir, targetFile string, logger *zerolog.Logger) bool {
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
			Str(logKeyPath, uvLockPath).
			Msg("Error checking for uv.lock file")
	}

	return false
}

// hasUvLockFileRecursive checks if any directory within dir (including dir itself)
// contains a uv.lock file, skipping directories in excludeDirs.
func hasUvLockFileRecursive(dir string, logger *zerolog.Logger) bool {
	found := false
	fpErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if logger != nil {
				logger.Debug().
					Err(err).
					Str(logKeyPath, path).
					Msg("Error accessing path during uv.lock search")
			}
			return nil // Continue walking despite errors
		}

		// Skip excluded directories
		if d.IsDir() {
			dirName := d.Name()
			if ExcludedUVLockFileDirs[dirName] {
				if logger != nil {
					logger.Debug().
						Str(logKeyPath, path).
						Msg("Skipping excluded directory during uv.lock search")
				}
				return fs.SkipDir
			}
			return nil
		}

		if d.Name() == LockFileName {
			found = true
			return fs.SkipAll // Stop walking, we found what we're looking for
		}

		return nil
	})

	if fpErr != nil && logger != nil {
		logger.Debug().
			Err(fpErr).
			Str(logKeyPath, dir).
			Msg("Error checking for uv.lock file")
	}

	return found
}

// HasUvLockFileInAnyDir checks if any of the input directories contains a uv.lock file.
func HasUvLockFileInAnyDir(inputDirs []string, targetFile string, allProjects bool, logger *zerolog.Logger) bool {
	for _, inputDir := range inputDirs {
		if HasUvLockFile(inputDir, targetFile, allProjects, logger) {
			return true
		}
	}
	return false
}
