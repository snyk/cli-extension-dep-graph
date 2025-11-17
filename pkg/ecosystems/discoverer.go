package ecosystems

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ProjectDefinition defines the structure of a project by specifying
// required and optional files or glob patterns that identify it.
type ProjectDefinition struct {
	// Name is a human-readable identifier for this project type (e.g., "maven", "npm")
	Name string

	// RequiredFiles are files or glob patterns that must be present for a project to be valid.
	// At least one file matching each required pattern must exist.
	RequiredFiles []string

	// OptionalFiles are files or glob patterns that may be present but are not mandatory.
	// These files will be included in the discovered project if they exist.
	OptionalFiles []string
}

// DiscoveredProject represents a project that was found during discovery,
// containing the project type and all matched files.
type DiscoveredProject struct {
	// Type is the name of the project type from the ProjectDefinition
	Type string

	// RootDir is the directory where the project was found
	RootDir string

	// RequiredFiles are the matched required files (relative to RootDir)
	RequiredFiles []string

	// OptionalFiles are the matched optional files (relative to RootDir)
	OptionalFiles []string
}

// AllFiles returns all files (required and optional) for this project.
func (p *DiscoveredProject) AllFiles() []string {
	all := make([]string, 0, len(p.RequiredFiles)+len(p.OptionalFiles))
	all = append(all, p.RequiredFiles...)
	all = append(all, p.OptionalFiles...)
	return all
}

// DiscovererOptions configures the behavior of the file discoverer.
type DiscovererOptions struct {
	// SearchDir is the root directory to start searching from
	SearchDir string

	// MaxDepth is the maximum directory depth to traverse (0 = only search SearchDir, -1 = unlimited)
	MaxDepth int

	// Exclude is a list of patterns to exclude from the search.
	// Patterns can be:
	//   - Exact names (e.g., "node_modules", ".git") - matches dirs or files with that name
	//   - Glob patterns (e.g., "*.test.js", "test_*.py") - matches using filepath.Match
	// Excluded directories will not be traversed.
	Exclude []string

	// TargetFile optionally specifies a specific file to scan.
	// If set, only projects containing this file (in their required or optional files) will be returned.
	// This allows plugins to filter out projects that don't match the target file.
	// For example: --file=package.json would return npm projects but not Python projects.
	TargetFile *string

	// ProjectDefinitions are the types of projects to search for
	ProjectDefinitions []ProjectDefinition
}

// Discoverer searches for project files based on provided definitions.
type Discoverer struct {
	options DiscovererOptions
}

// NewDiscoverer creates a new file discoverer with the given options.
func NewDiscoverer(options DiscovererOptions) *Discoverer {
	return &Discoverer{
		options: options,
	}
}

// Discover searches for projects matching the configured project definitions.
// It returns a slice of discovered projects, grouped by their root directory.
// If TargetFile is specified, only projects containing that file are returned.
func (d *Discoverer) Discover() ([]DiscoveredProject, error) {
	// Validate search directory
	info, err := os.Stat(d.options.SearchDir)
	if err != nil {
		return nil, fmt.Errorf("failed to access search directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("search path is not a directory: %s", d.options.SearchDir)
	}

	// Collect all directories to search
	dirsToSearch, err := d.collectDirectories()
	if err != nil {
		return nil, fmt.Errorf("failed to collect directories: %w", err)
	}

	// Search each directory for matching projects
	var projects []DiscoveredProject
	for _, dir := range dirsToSearch {
		dirProjects, err := d.searchDirectory(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to search directory %s: %w", dir, err)
		}
		projects = append(projects, dirProjects...)
	}

	// Filter by target file if specified
	if d.options.TargetFile != nil {
		projects = d.filterByTargetFile(projects, *d.options.TargetFile)
	}

	return projects, nil
}

// filterByTargetFile filters projects to only those containing the specified target file.
func (d *Discoverer) filterByTargetFile(projects []DiscoveredProject, targetFile string) []DiscoveredProject {
	var filtered []DiscoveredProject
	for _, project := range projects {
		// Check if target file matches any of the project's files
		for _, file := range project.AllFiles() {
			if file == targetFile || filepath.Base(file) == targetFile {
				filtered = append(filtered, project)
				break
			}
		}
	}
	return filtered
}

// collectDirectories walks the filesystem to collect all directories
// to search, respecting depth limits and exclusions.
func (d *Discoverer) collectDirectories() ([]string, error) {
	var dirs []string

	err := filepath.WalkDir(d.options.SearchDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip non-directories
		if !entry.IsDir() {
			return nil
		}

		// Calculate relative path and depth
		relPath, err := filepath.Rel(d.options.SearchDir, path)
		if err != nil {
			return err
		}

		// Root directory is always included
		if relPath == "." {
			dirs = append(dirs, path)
			return nil
		}

		// Check depth limit
		depth := strings.Count(relPath, string(filepath.Separator))
		if d.options.MaxDepth >= 0 && depth > d.options.MaxDepth {
			return fs.SkipDir
		}

		// Check if directory should be excluded
		if d.shouldExclude(path, entry.Name(), true) {
			return fs.SkipDir
		}

		dirs = append(dirs, path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return dirs, nil
}

// searchDirectory searches a single directory for projects matching the project definitions.
func (d *Discoverer) searchDirectory(dir string) ([]DiscoveredProject, error) {
	var projects []DiscoveredProject

	for _, projDef := range d.options.ProjectDefinitions {
		project, err := d.matchProjectDefinition(dir, projDef)
		if err != nil {
			return nil, err
		}
		if project != nil {
			projects = append(projects, *project)
		}
	}

	return projects, nil
}

// matchProjectDefinition checks if a directory matches a project definition
// and returns a DiscoveredProject if it does.
func (d *Discoverer) matchProjectDefinition(dir string, projDef ProjectDefinition) (*DiscoveredProject, error) {
	// Match required files
	var requiredMatches []string
	for _, pattern := range projDef.RequiredFiles {
		matches, err := d.matchPattern(dir, pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to match required pattern %s: %w", pattern, err)
		}
		if len(matches) == 0 {
			// Required file/pattern not found, this is not a valid project
			return nil, nil
		}
		requiredMatches = append(requiredMatches, matches...)
	}

	// Match optional files
	var optionalMatches []string
	for _, pattern := range projDef.OptionalFiles {
		matches, err := d.matchPattern(dir, pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to match optional pattern %s: %w", pattern, err)
		}
		optionalMatches = append(optionalMatches, matches...)
	}

	return &DiscoveredProject{
		Type:          projDef.Name,
		RootDir:       dir,
		RequiredFiles: requiredMatches,
		OptionalFiles: optionalMatches,
	}, nil
}

// matchPattern finds files in a directory matching a pattern or filename.
// Returns relative paths from the directory.
func (d *Discoverer) matchPattern(dir, pattern string) ([]string, error) {
	var matches []string

	// Check if pattern contains glob characters
	hasGlob := strings.ContainsAny(pattern, "*?[]")

	if hasGlob {
		// Use glob matching
		fullPattern := filepath.Join(dir, pattern)
		globMatches, err := filepath.Glob(fullPattern)
		if err != nil {
			return nil, err
		}

		for _, match := range globMatches {
			// Get basename for exclusion check
			basename := filepath.Base(match)

			// Skip if excluded
			if d.shouldExclude(match, basename, false) {
				continue
			}

			// Make path relative to directory
			relPath, err := filepath.Rel(dir, match)
			if err != nil {
				return nil, err
			}
			matches = append(matches, relPath)
		}
	} else {
		// Exact filename match
		fullPath := filepath.Join(dir, pattern)
		if _, err := os.Stat(fullPath); err == nil {
			// File exists, check if it should be excluded
			if !d.shouldExclude(fullPath, pattern, false) {
				matches = append(matches, pattern)
			}
		}
	}

	return matches, nil
}

// shouldExclude checks if a path should be excluded based on configured exclusion rules.
func (d *Discoverer) shouldExclude(fullPath, name string, isDir bool) bool {
	for _, pattern := range d.options.Exclude {
		// Try exact match on name
		if name == pattern {
			return true
		}

		// Try glob match on name
		matched, err := filepath.Match(pattern, name)
		if err == nil && matched {
			return true
		}

		// Try glob match on full path for more complex patterns
		matched, err = filepath.Match(pattern, fullPath)
		if err == nil && matched {
			return true
		}
	}

	return false
}
