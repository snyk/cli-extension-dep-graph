package poetry

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// pyprojectTOML is the minimum subset of pyproject.toml fields the
// poetry plugin needs to identify the root project. We deliberately keep
// it narrow — anything the depgraph builder doesn't read is left to
// poetry itself.
//
// Two manifest dialects exist in the wild:
//
//   - Poetry 1.x: `[tool.poetry]` table holds name/version.
//   - Poetry 2.x (PEP 621): `[project]` table holds name/version.
//
// We accept both.
type pyprojectTOML struct {
	Project struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"project"`

	Tool struct {
		Poetry struct {
			Name        string `toml:"name"`
			Version     string `toml:"version"`
			PackageMode *bool  `toml:"package-mode"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// rootPkg captures the resolved root project identity after honouring
// (in order) the explicit --project-name override, the manifest, and
// finally the directory-name fallback. version is whatever the manifest
// declared, or DefaultRootVersion if it didn't declare one.
type rootPkg struct {
	Name    string
	Version string
}

// readPyproject loads and parses pyproject.toml from dir. A missing file
// is a hard error — poetry projects always have one, and the legacy
// plugin errors out the same way (snyk-python-plugin/poetry.ts).
func readPyproject(dir string) (*pyprojectTOML, error) {
	path := filepath.Join(dir, PyprojectTomlFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p pyprojectTOML
	if err := toml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &p, nil
}

// resolveRootPkg derives the root package name + version, honouring the
// --project-name CLI override first. Resolution order:
//
//  1. override (when non-nil and non-empty) — set via SCAPluginOptions.Global.ProjectName.
//     The legacy snyk-python-plugin honours --project-name across all of
//     pip / pipenv / poetry / setup.py; we preserve that contract.
//  2. pyproject.toml `[project].name` (Poetry 2.x / PEP 621).
//  3. pyproject.toml `[tool.poetry].name` (Poetry 1.x).
//  4. dirname(scanDir) — final fallback for package-mode = false projects
//     and other manifests that intentionally omit a name.
//
// version is taken from whichever table provided the name, falling back
// to DefaultRootVersion when neither sets one.
func resolveRootPkg(manifest *pyprojectTOML, scanDir string, override *string) rootPkg {
	if override != nil && *override != "" {
		// Override doesn't tell us a version; pair it with whatever the
		// manifest declared (preferring [project] over [tool.poetry])
		// so downstream tooling that keys on version still has a value.
		return rootPkg{Name: *override, Version: manifestVersion(manifest)}
	}
	if manifest != nil {
		if manifest.Project.Name != "" {
			return rootPkg{Name: manifest.Project.Name, Version: orDefault(manifest.Project.Version)}
		}
		if manifest.Tool.Poetry.Name != "" {
			return rootPkg{Name: manifest.Tool.Poetry.Name, Version: orDefault(manifest.Tool.Poetry.Version)}
		}
	}
	// Final fallback: scan directory base. Matches the legacy plugin's
	// `_root` behaviour but with a more useful name when we can derive
	// one from the filesystem.
	if base := filepath.Base(scanDir); base != "" && base != "." && base != "/" {
		return rootPkg{Name: base, Version: DefaultRootVersion}
	}
	return rootPkg{Name: DefaultRootName, Version: DefaultRootVersion}
}

// manifestVersion returns whichever table declares a version, preferring
// the modern `[project]` table over `[tool.poetry]`.
func manifestVersion(m *pyprojectTOML) string {
	if m == nil {
		return DefaultRootVersion
	}
	if m.Project.Version != "" {
		return m.Project.Version
	}
	if m.Tool.Poetry.Version != "" {
		return m.Tool.Poetry.Version
	}
	return DefaultRootVersion
}

func orDefault(v string) string {
	if v == "" {
		return DefaultRootVersion
	}
	return v
}
