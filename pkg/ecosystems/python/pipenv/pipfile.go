package pipenv

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	if _, ok := spec["file"].(string); ok {
		return name
	}

	return withExtras(name, spec)
}

// withExtras appends the entry's extras to its name, as `name[a,b]`.
func withExtras(name string, spec map[string]interface{}) string {
	if extras, ok := spec["extras"].([]interface{}); ok && len(extras) > 0 {
		extraStrs := make([]string, len(extras))
		for i, e := range extras {
			extraStrs[i] = fmt.Sprintf("%v", e)
		}
		return fmt.Sprintf("%s[%s]", name, strings.Join(extraStrs, ","))
	}

	return name
}

// ToRequirements is ToPackageNames for pip's dry run with component
// metadata. Path and file entries become PEP 508 direct references
// (`name @ file:///abs/dir`, or the URL a file entry gives), resolved
// relative to pipfileDir, so pip builds them from disk rather than resolving
// their name from an index: by name, a local `utils` resolves to an
// unrelated index package, with its hash. This matches snyk-python-plugin,
// which reports the locally installed project.
//
// An entry whose local path is not a Python project (no pyproject.toml,
// setup.py or setup.cfg) or whose file does not exist is returned in dropped
// instead: isolated builds copy only the Pipfile and its lock, and pip would
// fail the whole project on it. Both lists are sorted.
func (p *Pipfile) ToRequirements(includeDevDeps bool, pipfileDir string) (reqs, dropped []string) {
	add := func(pkgs map[string]interface{}) {
		for name, spec := range pkgs {
			req := extractPackageName(name, spec)
			if req == "" {
				continue
			}
			if m, ok := spec.(map[string]interface{}); ok {
				if ref, local, ok := directReference(m, pipfileDir); ok {
					if local != "" && !isInstallable(local) {
						dropped = append(dropped, name)
						continue
					}
					req = withExtras(name, m) + " @ " + ref
				}
			}
			reqs = append(reqs, req)
		}
	}
	add(p.Packages)
	if includeDevDeps {
		add(p.DevPkgs)
	}
	sort.Strings(reqs)
	sort.Strings(dropped)
	return reqs, dropped
}

// directReference returns the URL a path or file entry points at and, for a
// local one, its absolute path. A file entry may already be a URL.
func directReference(spec map[string]interface{}, pipfileDir string) (ref, local string, ok bool) {
	ref, ok = spec["path"].(string)
	if !ok {
		if ref, ok = spec["file"].(string); !ok {
			return "", "", false
		}
		if u, err := url.Parse(ref); err == nil && len(u.Scheme) > 1 {
			return ref, "", true
		}
	}
	if !filepath.IsAbs(ref) {
		ref = filepath.Join(pipfileDir, ref)
	}
	local = filepath.Clean(ref)
	return fileURL(local), local, true
}

// fileURL percent-encodes every byte outside RFC 3986's unreserved set, "/"
// and ":". url.URL leaves sub-delimiters such as ";" alone, which PEP 508
// parsers read as the start of a marker, and pip decodes the escapes when it
// turns the URL back into a path.
func fileURL(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a Windows drive path, file:///C:/...
	}
	var b strings.Builder
	b.WriteString("file://")
	for i := 0; i < len(p); i++ {
		c := p[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~/:", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// isInstallable reports whether pip could build a local path: a file, or a
// directory holding Python project metadata.
func isInstallable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return true
	}
	for _, f := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			return true
		}
	}
	return false
}
