package discovery

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
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
func FindFiles(ctx context.Context, log logger.Logger, rootDir string, options ...FindOption) ([]FindResult, error) {
	if log == nil {
		log = logger.Nop()
	}

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

	log.Debug(ctx, "Starting file discovery",
		logger.Attr("root_dir", absRoot),
		logger.Attr("target_files", opts.targetFiles),
		logger.Attr("include_globs", opts.includeGlobs),
		logger.Attr("exclude_globs", opts.excludeGlobs))

	// Use a map to deduplicate results by absolute path
	resultMap := make(map[string]FindResult)

	// Find all target files
	for _, targetFile := range opts.targetFiles {
		result, err := findTargetFile(ctx, log, absRoot, targetFile, opts.excludeGlobs)
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
		globResults, err := walkDirectory(ctx, log, absRoot, opts)
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

	log.Info(ctx, "File discovery completed",
		logger.Attr("root_dir", absRoot),
		logger.Attr("files_found", len(results)))

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
func findTargetFile(ctx context.Context, log logger.Logger, absRoot, targetFile string, excludePatterns []string) (FindResult, error) {
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
		log.Debug(ctx, "Failed to compute relative path for target file",
			logger.Attr(logKeyFile, targetPath),
			logger.Err(err))
		relPath = targetPath
	}

	// Check if excluded - return empty result but no error
	if isExcluded(ctx, log, filepath.Base(relPath), relPath, excludePatterns) {
		log.Debug(ctx, "Target file excluded by pattern", logger.Attr(logKeyFile, targetFile))
		return FindResult{}, nil
	}

	log.Debug(ctx, "Found target file", logger.Attr(logKeyFile, targetPath))
	return FindResult{
		Path:    targetPath,
		RelPath: relPath,
	}, nil
}

// walkDirectory traverses the directory tree and finds files matching the include pattern.
func walkDirectory(ctx context.Context, log logger.Logger, absRoot string, opts *findOptions) ([]FindResult, error) {
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
			log.Error(ctx, "Error accessing path", logger.Attr(logKeyPath, path), logger.Err(err))
			return nil // Continue walking despite errors
		}

		relPath, err := filepath.Rel(absRoot, path)
		if err != nil {
			log.Error(ctx, "Failed to compute relative path", logger.Attr(logKeyPath, path), logger.Err(err))
			return nil
		}

		// Handle directories
		if d.IsDir() {
			return handleDirectory(ctx, log, d, relPath, opts.excludeGlobs)
		}

		// Check exclusions and pattern match for files
		if shouldIncludeFile(ctx, log, d, relPath, opts) {
			results = append(results, FindResult{
				Path:    path,
				RelPath: relPath,
			})
			log.Debug(ctx, "Matched file", logger.Attr(logKeyFile, relPath))
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", absRoot, err)
	}

	return results, nil
}

// handleDirectory checks if a directory should be excluded and returns fs.SkipDir if so.
func handleDirectory(ctx context.Context, log logger.Logger, d fs.DirEntry, relPath string, excludePatterns []string) error {
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
			log.Error(ctx, "Invalid exclude pattern for directory", logger.Attr(logKeyPattern, pattern), logger.Err(err))
			continue
		}
		if matched {
			log.Debug(ctx, "Excluding directory by path", logger.Attr(logKeyDir, relPath), logger.Attr(logKeyPattern, pattern))
			return fs.SkipDir
		}

		// Check directory name (matches anywhere in tree)
		matched, err = filepath.Match(pattern, name)
		if err != nil {
			log.Error(ctx, "Invalid exclude pattern for directory", logger.Attr(logKeyPattern, pattern), logger.Err(err))
			continue
		}
		if matched {
			log.Debug(ctx, "Excluding directory by name", logger.Attr(logKeyDir, name), logger.Attr(logKeyPattern, pattern))
			return fs.SkipDir
		}
	}

	return nil
}

// shouldIncludeFile determines if a file should be included in results.
// Returns true if the file matches any of the include globs and is not excluded.
func shouldIncludeFile(ctx context.Context, log logger.Logger, d fs.DirEntry, relPath string, opts *findOptions) bool {
	name := d.Name()

	// Check exclusions first (most likely to filter out files)
	if isExcluded(ctx, log, name, relPath, opts.excludeGlobs) {
		log.Debug(ctx, "Excluding file", logger.Attr(logKeyFile, relPath))
		return false
	}

	// Match against any include pattern (already validated in validateInputs)
	for _, pattern := range opts.includeGlobs {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			log.Error(ctx, "Invalid include pattern for file", logger.Attr(logKeyPattern, pattern), logger.Err(err))
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
func isExcluded(ctx context.Context, log logger.Logger, name, relPath string, excludePatterns []string) bool {
	if len(excludePatterns) == 0 {
		return false
	}

	for _, pattern := range excludePatterns {
		// Check by name
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			log.Error(ctx, "Invalid exclude pattern", logger.Attr(logKeyPattern, pattern), logger.Err(err))
			continue
		}
		if matched {
			return true
		}

		// Check by relative path
		matched, err = filepath.Match(pattern, relPath)
		if err != nil {
			log.Error(ctx, "Invalid exclude pattern", logger.Attr(logKeyPattern, pattern), logger.Err(err))
			continue
		}
		if matched {
			return true
		}
	}

	return false
}
