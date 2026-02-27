package discovery

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	logKeyFile    = "file"
	logKeyPath    = "path"
	logKeyDir     = "dir"
	logKeyError   = "error"
	logKeyPattern = "pattern"
)

// findOptions configures file discovery behavior.
type findOptions struct {
	targetFiles  []string
	includeGlobs []string
	excludeGlobs []string
}

// FindOption is a functional option for configuring file discovery.
type FindOption func(*findOptions)

// WithTargetFile adds a specific file to find.
func WithTargetFile(file string) FindOption {
	return func(o *findOptions) {
		o.targetFiles = append(o.targetFiles, file)
	}
}

// WithTargetFiles adds multiple specific files to find.
func WithTargetFiles(files ...string) FindOption {
	return func(o *findOptions) {
		o.targetFiles = append(o.targetFiles, files...)
	}
}

// WithInclude adds a glob pattern for files to include (e.g., "requirements*.txt").
func WithInclude(pattern string) FindOption {
	return func(o *findOptions) {
		o.includeGlobs = append(o.includeGlobs, pattern)
	}
}

// WithIncludes adds multiple glob patterns for files to include.
func WithIncludes(patterns ...string) FindOption {
	return func(o *findOptions) {
		o.includeGlobs = append(o.includeGlobs, patterns...)
	}
}

// WithExclude adds a glob pattern for files/directories to exclude (e.g., "node_modules").
func WithExclude(pattern string) FindOption {
	return func(o *findOptions) {
		o.excludeGlobs = append(o.excludeGlobs, pattern)
	}
}

// WithExcludes adds multiple glob patterns for files/directories to exclude.
func WithExcludes(patterns ...string) FindOption {
	return func(o *findOptions) {
		o.excludeGlobs = append(o.excludeGlobs, patterns...)
	}
}

// WithCommonExcludes adds common exclude patterns for files/directories.
func WithCommonExcludes() FindOption {
	return WithExcludes(commonExcludes...)
}

// FindResult represents a discovered file.
type FindResult struct {
	Path    string // Absolute path to the file
	RelPath string // Path relative to the root directory
}

// FindFiles discovers files in a directory based on the provided options.
// It efficiently traverses the directory tree and returns matching files.
//
// Finds all files specified in TargetFiles and all files matching any IncludeGlobs pattern.
// Exclude pattern filters out directories and files from both modes.
// Returns a deduplicated list of matching files.
//
// The search can be canceled via the context.
func FindFiles(ctx context.Context, rootDir string, options ...FindOption) ([]FindResult, error) {
	// Apply options
	opts := &findOptions{
		targetFiles:  []string{},
		includeGlobs: []string{},
		excludeGlobs: []string{},
	}
	for _, opt := range options {
		opt(opts)
	}

	if err := validateInputs(rootDir, opts); err != nil {
		return nil, err
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for %s: %w", rootDir, err)
	}

	slog.Debug("Starting file discovery",
		slog.String("root_dir", absRoot),
		slog.Any("target_files", opts.targetFiles),
		slog.Any("include_globs", opts.includeGlobs),
		slog.Any("exclude_globs", opts.excludeGlobs))

	// Use a map to deduplicate results by absolute path
	resultMap := make(map[string]FindResult)

	// Find all target files
	for _, targetFile := range opts.targetFiles {
		result, err := findTargetFile(absRoot, targetFile, opts.excludeGlobs)
		if err != nil {
			return nil, err
		}
		// Only add if not excluded (empty result means excluded)
		if result.Path != "" {
			resultMap[result.Path] = result
		}
	}

	// Walk directory for pattern matching if any globs specified
	if len(opts.includeGlobs) > 0 {
		globResults, err := walkDirectory(ctx, absRoot, opts)
		if err != nil {
			return nil, err
		}
		for _, result := range globResults {
			resultMap[result.Path] = result
		}
	}

	// Convert map to slice
	results := make([]FindResult, 0, len(resultMap))
	for _, result := range resultMap {
		results = append(results, result)
	}

	slog.Info("File discovery completed",
		slog.String("root_dir", absRoot),
		slog.Int("files_found", len(results)))

	return results, nil
}

// validateInputs checks that required parameters are provided.
func validateInputs(rootDir string, opts *findOptions) error {
	if rootDir == "" {
		return fmt.Errorf("rootDir cannot be empty")
	}
	if opts == nil {
		return fmt.Errorf("opts cannot be nil")
	}
	if len(opts.targetFiles) == 0 && len(opts.includeGlobs) == 0 {
		return fmt.Errorf("at least one target file or include pattern must be specified")
	}

	// Validate include patterns
	for _, pattern := range opts.includeGlobs {
		if _, err := filepath.Match(pattern, "test"); err != nil {
			return fmt.Errorf("invalid include pattern %s: %w", pattern, err)
		}
	}

	// Validate exclude patterns
	for _, pattern := range opts.excludeGlobs {
		if _, err := filepath.Match(pattern, "test"); err != nil {
			return fmt.Errorf("invalid exclude pattern %s: %w", pattern, err)
		}
	}

	return nil
}

// findTargetFile attempts to find a specific file by path.
// Returns an error if the file is not found or is a directory.
// Returns nil error with empty result if the file is excluded.
func findTargetFile(absRoot, targetFile string, excludePatterns []string) (FindResult, error) {
	targetPath := targetFile
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(absRoot, targetPath)
	}
	targetPath = filepath.Clean(targetPath)

	info, err := os.Stat(targetPath)
	if err != nil {
		return FindResult{}, fmt.Errorf("target file %s not found: %w", targetFile, err)
	}
	if info.IsDir() {
		return FindResult{}, fmt.Errorf("target file %s is a directory", targetFile)
	}

	relPath, err := filepath.Rel(absRoot, targetPath)
	if err != nil {
		slog.Debug("Failed to compute relative path for target file",
			slog.String(logKeyFile, targetPath),
			slog.Any(logKeyError, err))
		relPath = targetPath
	}

	// Check if excluded - return empty result but no error
	if isExcluded(filepath.Base(relPath), relPath, excludePatterns) {
		slog.Debug("Target file excluded by pattern", slog.String(logKeyFile, targetFile))
		return FindResult{}, nil
	}

	slog.Debug("Found target file", slog.String(logKeyFile, targetPath))
	return FindResult{
		Path:    targetPath,
		RelPath: relPath,
	}, nil
}

// walkDirectory traverses the directory tree and finds files matching the include pattern.
func walkDirectory(ctx context.Context, absRoot string, opts *findOptions) ([]FindResult, error) {
	// Pre-allocate with reasonable capacity to reduce allocations
	results := make([]FindResult, 0, 16)

	err := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			slog.Warn("Error accessing path", slog.String(logKeyPath, path), slog.Any(logKeyError, err))
			return nil // Continue walking despite errors
		}

		relPath, err := filepath.Rel(absRoot, path)
		if err != nil {
			slog.Warn("Failed to compute relative path", slog.String(logKeyPath, path), slog.Any(logKeyError, err))
			return nil
		}

		// Handle directories
		if d.IsDir() {
			return handleDirectory(d, relPath, opts.excludeGlobs)
		}

		// Check exclusions and pattern match for files
		if shouldIncludeFile(d, relPath, opts) {
			results = append(results, FindResult{
				Path:    path,
				RelPath: relPath,
			})
			slog.Debug("Matched file", slog.String(logKeyFile, relPath))
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", absRoot, err)
	}

	return results, nil
}

// handleDirectory checks if a directory should be excluded and returns fs.SkipDir if so.
func handleDirectory(d fs.DirEntry, relPath string, excludePatterns []string) error {
	if len(excludePatterns) == 0 {
		return nil
	}

	// Never exclude the root directory
	if relPath == "." {
		return nil
	}

	name := d.Name()
	for _, pattern := range excludePatterns {
		// Check relative path first (more specific)
		matched, err := filepath.Match(pattern, relPath)
		if err != nil {
			slog.Warn("Invalid exclude pattern for directory", slog.String(logKeyPattern, pattern), slog.Any(logKeyError, err))
			continue
		}
		if matched {
			slog.Debug("Excluding directory by path", slog.String(logKeyDir, relPath), slog.String(logKeyPattern, pattern))
			return fs.SkipDir
		}

		// Check directory name (matches anywhere in tree)
		matched, err = filepath.Match(pattern, name)
		if err != nil {
			slog.Warn("Invalid exclude pattern for directory", slog.String(logKeyPattern, pattern), slog.Any(logKeyError, err))
			continue
		}
		if matched {
			slog.Debug("Excluding directory by name", slog.String(logKeyDir, name), slog.String(logKeyPattern, pattern))
			return fs.SkipDir
		}
	}

	return nil
}

// shouldIncludeFile determines if a file should be included in results.
// Returns true if the file matches any of the include globs and is not excluded.
func shouldIncludeFile(d fs.DirEntry, relPath string, opts *findOptions) bool {
	name := d.Name()

	// Check exclusions first (most likely to filter out files)
	if isExcluded(name, relPath, opts.excludeGlobs) {
		slog.Debug("Excluding file", slog.String(logKeyFile, relPath))
		return false
	}

	// Match against any include pattern (already validated in validateInputs)
	for _, pattern := range opts.includeGlobs {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			slog.Warn("Invalid include pattern for file", slog.String(logKeyPattern, pattern), slog.Any(logKeyError, err))
			continue
		}
		if matched {
			return true
		}
	}

	return false
}

// isExcluded checks if a file/directory matches any of the exclude patterns.
// Checks both the name (for matching anywhere in tree) and relPath (for specific paths).
func isExcluded(name, relPath string, excludePatterns []string) bool {
	if len(excludePatterns) == 0 {
		return false
	}

	for _, pattern := range excludePatterns {
		// Check by name
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			slog.Warn("Invalid exclude pattern", slog.String(logKeyPattern, pattern), slog.Any(logKeyError, err))
			continue
		}
		if matched {
			return true
		}

		// Check by relative path
		matched, err = filepath.Match(pattern, relPath)
		if err != nil {
			slog.Warn("Invalid exclude pattern", slog.String(logKeyPattern, pattern), slog.Any(logKeyError, err))
			continue
		}
		if matched {
			return true
		}
	}

	return false
}
