package gradle

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// errGradleNotFound is returned when the gradle binary is not in PATH.
var errGradleNotFound = errors.New("gradle binary not found in PATH")

// osDetector returns the current operating system name.
// This variable can be overridden in tests to mock different platforms.
var osDetector = func() string {
	return runtime.GOOS
}

// ResolveGradleBinary returns the gradle executable to use for a given project directory.
// It looks for the platform-appropriate Gradle wrapper when not skipped:
// - On Windows: gradlew.bat
// - On Unix-like systems: gradlew
// If no wrapper is found or skipped, falls back to the gradle binary in PATH.
func ResolveGradleBinary(projectDir string, skipWrapper bool) (string, error) {
	if !skipWrapper {
		// Search for wrapper starting from the project directory and walking up
		if wrapper := findWrapperInTreeFromPath(projectDir); wrapper != "" {
			return wrapper, nil
		}
	}

	// Fall back to system gradle, but verify it exists
	resolved, err := exec.LookPath("gradle")
	if err != nil {
		return "", errGradleNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	return resolved, nil
}

// findWrapperInTreeFromPath searches for the platform-appropriate gradlew wrapper starting
// from startDir and walking up the directory tree until an executable wrapper is found
// or the filesystem root is reached.
func findWrapperInTreeFromPath(startDir string) string {
	// Choose wrapper based on OS - these are mutually exclusive
	var wrapperName string
	if osDetector() == "windows" {
		wrapperName = "gradlew.bat"
	} else {
		wrapperName = "gradlew"
	}

	dir := startDir
	for {
		path := filepath.Join(dir, wrapperName)
		if isExecutable(path) {
			return path
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	// On Windows, executable-ness is determined by file extension via registry associations.
	// By default .bat files are registered as executable and making them non-executable
	// would cause system-wide issues. So if the file exists, assume it's executable.
	if osDetector() == "windows" {
		return true
	}

	// On Unix-like systems, check permission bits
	return info.Mode()&0o111 != 0
}
