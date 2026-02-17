package pipenv

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// Platform constants for sys_platform markers.
const (
	platformWin32  = "win32"
	platformDarwin = "darwin"
	platformLinux  = "linux"
)

// Pipfile represents the structure of a Pipfile.
type Pipfile struct {
	Source   []PipfileSource          `toml:"source"`
	Packages map[string]interface{}   `toml:"packages"`
	DevPkgs  map[string]interface{}   `toml:"dev-packages"`
	Requires PipfileRequiresPythonVer `toml:"requires"`
}

// PipfileSource represents a package source in the Pipfile.
type PipfileSource struct {
	Name   string `toml:"name"`
	URL    string `toml:"url"`
	Verify bool   `toml:"verify_ssl"`
}

// PipfileRequiresPythonVer represents the Python version requirements.
type PipfileRequiresPythonVer struct {
	PythonVersion string `toml:"python_version"`
}

// ParsePipfile reads and parses a Pipfile from the given path.
func ParsePipfile(path string) (*Pipfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile: %w", err)
	}

	var pipfile Pipfile
	if err := toml.Unmarshal(data, &pipfile); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile: %w", err)
	}

	return &pipfile, nil
}

// matchesPlatformMarker checks if the current platform matches the given marker.
// Supports common markers like sys_platform == 'win32', sys_platform == 'darwin', sys_platform == 'linux'.
func matchesPlatformMarker(marker string) bool {
	if !strings.Contains(marker, "sys_platform") {
		// If we can't parse the marker, include the package (let pip handle it)
		return true
	}

	currentPlatform := getCurrentPlatform()
	platforms := []string{platformWin32, platformDarwin, platformLinux}

	for _, platform := range platforms {
		if !strings.Contains(marker, "'"+platform+"'") && !strings.Contains(marker, "\""+platform+"\"") {
			continue
		}
		// Found a platform marker - check if it's != or ==
		if strings.Contains(marker, "!=") {
			return currentPlatform != platform
		}
		return currentPlatform == platform
	}

	return true
}

// getCurrentPlatform returns the current platform in Python's sys_platform format.
func getCurrentPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return platformWin32
	case platformDarwin:
		return platformDarwin
	case platformLinux:
		return platformLinux
	default:
		return runtime.GOOS
	}
}

// ToPackageNames converts Pipfile packages to just package names without version specifiers.
// This is useful when using a lockfile to constrain versions via pip's -c flag.
func (p *Pipfile) ToPackageNames(includeDevDeps bool) []string {
	var names []string

	// Process regular packages
	for name, spec := range p.Packages {
		pkgName := extractPackageName(name, spec)
		if pkgName != "" {
			names = append(names, pkgName)
		}
	}

	// Process dev packages if requested
	if includeDevDeps {
		for name, spec := range p.DevPkgs {
			pkgName := extractPackageName(name, spec)
			if pkgName != "" {
				names = append(names, pkgName)
			}
		}
	}

	return names
}

// extractPackageName extracts just the package name from a Pipfile entry,
// handling platform markers, git dependencies, and extras.
func extractPackageName(name string, spec interface{}) string {
	switch v := spec.(type) {
	case string:
		// Simple version specifier - just return the name
		return name
	case map[string]interface{}:
		// Complex specifier - check markers and return name with extras if present
		return extractComplexPackageName(name, v)
	default:
		// Unknown format, just return the package name
		return name
	}
}

// extractComplexPackageName handles complex Pipfile package specifications.
func extractComplexPackageName(name string, spec map[string]interface{}) string {
	// Check for platform markers - skip packages that don't match current platform
	if markers, ok := spec["markers"].(string); ok {
		if !matchesPlatformMarker(markers) {
			return ""
		}
	}

	// For git/path/url dependencies, return the name as-is
	// (these will be handled specially by pip)
	if _, ok := spec["git"].(string); ok {
		return name
	}
	if _, ok := spec["path"].(string); ok {
		return name
	}
	if _, ok := spec["url"].(string); ok {
		return name
	}

	// Handle extras - include them in the package name
	if extras, ok := spec["extras"].([]interface{}); ok && len(extras) > 0 {
		extraStrs := make([]string, len(extras))
		for i, e := range extras {
			extraStrs[i] = fmt.Sprintf("%v", e)
		}
		return fmt.Sprintf("%s[%s]", name, strings.Join(extraStrs, ","))
	}

	return name
}
