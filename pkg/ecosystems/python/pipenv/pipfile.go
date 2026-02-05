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

// ToRequirements converts Pipfile packages to requirements.txt format.
// Each package is converted to a line like "package==version" or just "package"
// depending on how it's specified in the Pipfile.
func (p *Pipfile) ToRequirements(includeDevDeps bool) []string {
	var requirements []string

	// Process regular packages
	for name, spec := range p.Packages {
		req := formatRequirement(name, spec)
		if req != "" {
			requirements = append(requirements, req)
		}
	}

	// Process dev packages if requested
	if includeDevDeps {
		for name, spec := range p.DevPkgs {
			req := formatRequirement(name, spec)
			if req != "" {
				requirements = append(requirements, req)
			}
		}
	}

	return requirements
}

// formatRequirement converts a Pipfile package entry to requirements.txt format.
func formatRequirement(name string, spec interface{}) string {
	switch v := spec.(type) {
	case string:
		// Simple version specifier like "*" or ">=1.0"
		if v == "*" {
			return name
		}
		return name + v
	case map[string]interface{}:
		// Complex specifier with version, extras, git, etc.
		return formatComplexRequirement(name, v)
	default:
		// Unknown format, just return the package name
		return name
	}
}

// formatComplexRequirement handles complex Pipfile package specifications.
func formatComplexRequirement(name string, spec map[string]interface{}) string {
	// Check for platform markers - skip packages that don't match current platform
	if markers, ok := spec["markers"].(string); ok {
		if !matchesPlatformMarker(markers) {
			return ""
		}
	}

	// Check for git/VCS dependencies
	if git, ok := spec["git"].(string); ok {
		return formatGitRequirement(name, git, spec)
	}

	// Check for path dependencies
	if path, ok := spec["path"].(string); ok {
		return formatPathRequirement(path, spec)
	}

	// Check for URL dependencies
	if url, ok := spec["url"].(string); ok {
		return url
	}

	// Standard package with version and possibly extras
	var parts []string
	parts = append(parts, name)

	// Handle extras
	if extras, ok := spec["extras"].([]interface{}); ok && len(extras) > 0 {
		extraStrs := make([]string, len(extras))
		for i, e := range extras {
			extraStrs[i] = fmt.Sprintf("%v", e)
		}
		parts[0] = fmt.Sprintf("%s[%s]", name, strings.Join(extraStrs, ","))
	}

	// Handle version
	if version, ok := spec["version"].(string); ok && version != "*" {
		return parts[0] + version
	}

	return parts[0]
}

// formatGitRequirement formats a git-based dependency.
func formatGitRequirement(name, gitURL string, spec map[string]interface{}) string {
	var ref string
	if r, ok := spec["ref"].(string); ok {
		ref = r
	} else if tag, ok := spec["tag"].(string); ok {
		ref = tag
	} else if branch, ok := spec["branch"].(string); ok {
		ref = branch
	}

	// Format: package @ git+https://github.com/user/repo@ref
	result := fmt.Sprintf("%s @ git+%s", name, gitURL)
	if ref != "" {
		result += "@" + ref
	}
	return result
}

// formatPathRequirement formats a path-based dependency.
func formatPathRequirement(path string, spec map[string]interface{}) string {
	editable := false
	if e, ok := spec["editable"].(bool); ok {
		editable = e
	}

	if editable {
		return "-e " + path
	}
	return path
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
