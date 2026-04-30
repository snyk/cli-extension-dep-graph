package gradle

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

//go:embed init/snyk-deps-init.gradle
var embeddedInitScript []byte

const (
	PluginName = "gradle"
	// logAttrProjectDir is the structured-log key used when logging the Gradle project directory.
	logAttrProjectDir = "project_dir"
)

// Plugin is the Gradle SCA plugin.  It has no exported fields; all
// configuration is passed through ecosystems.SCAPluginOptions at call time.
type Plugin struct{}

// Compile-time assertion that Plugin satisfies the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers and builds Gradle dependency graphs for the
// given directory.
//
// Behavior:
//   - If --target-file points to a build.gradle / build.gradle.kts, that
//     file's directory is used as the Gradle project root.
//   - Otherwise the plugin looks for build.gradle or build.gradle.kts at the
//     top level of dir.  If neither exists, an empty result is returned so
//     that the caller can fall back to the legacy CLI.
//   - The embedded snyk-deps-init.gradle is always written to a temp file and
//     passed to Gradle via --init-script (required for dependency graph generation).
//     Users can provide additional init scripts via --init-script which are passed
//     as supplementary --init-script flags.
//   - The Gradle invocation always uses --no-daemon, --no-parallel for predictable,
//     isolated execution.
//   - The init script traverses all sub-projects automatically; each sub-project
//     yields one SCAResult.  Use --gradle-sub-project to filter to a single one.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	if log == nil {
		log = logger.Nop()
	}

	files, err := p.discoverGradleFiles(ctx, dir, options)
	if err != nil {
		return nil, fmt.Errorf("gradle: failed to discover files: %w", err)
	}
	if len(files) == 0 {
		log.Debug(ctx, "No Gradle files found, skipping", logger.Attr("dir", dir))
		return &ecosystems.PluginResult{}, nil
	}

	allResults, allProcessedFiles, err := p.processGradleFiles(ctx, log, files, dir, options)
	if err != nil {
		return nil, err
	}

	return &ecosystems.PluginResult{
		Results:        allResults,
		ProcessedFiles: allProcessedFiles,
	}, nil
}

// discoverGradleFiles discovers Gradle build files based on the provided options.
func (p Plugin) discoverGradleFiles(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]discovery.FindResult, error) {
	switch {
	case options.Global.TargetFile != nil:
		// Validate target file is a Gradle build file
		if !isBuildFile(*options.Global.TargetFile) {
			return nil, nil // Not a Gradle build file, skip
		}
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("failed to find target file: %w", err)
		}
		return files, nil

	case options.Global.AllProjects:
		return p.discoverAllGradleProjects(ctx, dir, options)

	default:
		// Find best build file in root directory (priority order)
		return p.findBestBuildFile(dir)
	}
}

// findBestBuildFile finds the highest priority Gradle file in the root directory only.
// Priority order: build.gradle, build.gradle.kts, settings.gradle, settings.gradle.kts
// Build files are scan targets; settings files indicate project root for multi-project builds.
func (p Plugin) findBestBuildFile(dir string) ([]discovery.FindResult, error) {
	// Check all files in priority order
	gradleFiles := []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}

	for _, filename := range gradleFiles {
		filePath := filepath.Join(dir, filename)
		if _, err := os.Stat(filePath); err == nil {
			return []discovery.FindResult{{
				Path:    filePath,
				RelPath: filename,
			}}, nil
		}
	}

	return nil, nil // No Gradle files found
}

// processGradleFiles processes all discovered Gradle files with directory-based deduplication.
func (p Plugin) processGradleFiles(
	ctx context.Context,
	log logger.Logger,
	files []discovery.FindResult,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]ecosystems.SCAResult, []string, error) {
	// Sort by path depth to process parent directories first
	sort.Slice(files, func(i, j int) bool {
		depthI := strings.Count(files[i].Path, string(filepath.Separator))
		depthJ := strings.Count(files[j].Path, string(filepath.Separator))
		return depthI < depthJ
	})

	var allResults []ecosystems.SCAResult
	var allProcessedFiles []string
	processedDirs := make(map[string]bool)

	initScriptPath, cleanup, err := resolveInitScript()
	if err != nil {
		return nil, nil, fmt.Errorf("gradle: failed to prepare init script: %w", err)
	}
	defer cleanup()

	// Build extra args once upfront - user init scripts should be relative to original scan directory
	extraArgs, err := buildExtraArgs(dir, options)
	if err != nil {
		return nil, nil, fmt.Errorf("gradle: %w", err)
	}

	for _, discoveredFile := range files {
		projectDir := filepath.Dir(discoveredFile.Path)
		relativeProjectDir := filepath.Dir(discoveredFile.RelPath)

		// Skip if we've already processed this directory
		if processedDirs[relativeProjectDir] {
			log.Debug(ctx, "Skipping already processed directory",
				logger.Attr("dir", projectDir),
				logger.Attr("file", discoveredFile.RelPath))
			continue
		}

		// Try to resolve Gradle binary first - if it fails, add error result and mark as processed
		gradleBinary, err := ResolveGradleBinary(projectDir, options.Gradle.SkipWrapper)
		if err != nil {
			log.Error(ctx, "Gradle binary resolution failed",
				logger.Attr(logAttrProjectDir, projectDir),
				logger.Err(err))
			// Add error result and mark directory as processed (failed)
			errResult := gradleErrorResult(dir, discoveredFile.Path, fmt.Errorf("binary resolution failed: %w", err))
			allResults = append(allResults, errResult)
			processedDirs[relativeProjectDir] = true
			continue // Skip to next file
		}

		// Check if we discovered a settings file (project root) vs build file (scan target)
		isSettingsFile := isSettingsFile(discoveredFile.RelPath)
		if isSettingsFile {
			log.Debug(ctx, "Gradle settings file found, will scan sub-projects",
				logger.Attr("settings_file", discoveredFile.RelPath))
		}

		log.Debug(ctx, "Processing Gradle project",
			logger.Attr(logAttrProjectDir, projectDir),
			logger.Attr("file", discoveredFile.RelPath))

		log.Debug(ctx, "Running Gradle dependency resolution",
			logger.Attr(logAttrProjectDir, projectDir),
			logger.Attr("init_script", initScriptPath),
			logger.Attr("gradle_binary", gradleBinary))

		data, err := runInitScript(ctx, projectDir, gradleBinary, initScriptPath, extraArgs)
		if err != nil {
			log.Error(ctx, "Gradle execution failed",
				logger.Attr(logAttrProjectDir, projectDir),
				logger.Err(err))
			// Surface as an error result rather than a hard failure
			errResult := gradleErrorResult(dir, discoveredFile.Path, err)
			allResults = append(allResults, errResult)
			continue
		}

		parsed, err := parseDependencyGraphJSON(data)
		if err != nil {
			return nil, nil, fmt.Errorf("gradle: failed to parse init script output: %w", err)
		}

		// For settings files, don't pass them as build file fallback since they're not scan targets
		buildFileForFallback := discoveredFile.Path
		if isSettingsFile {
			buildFileForFallback = "" // Let Gradle init script determine actual build files
		}

		results, processedFiles := p.convertProjects(ctx, log, parsed, dir, buildFileForFallback, options)

		allResults = append(allResults, results...)
		allProcessedFiles = append(allProcessedFiles, processedFiles...)

		// Mark all directories that were processed by this Gradle run
		for _, processedFile := range processedFiles {
			processedDir := filepath.Dir(processedFile)
			processedDirs[processedDir] = true
		}

		// Also mark the directory we ran from as processed
		processedDirs[relativeProjectDir] = true
	}

	return allResults, allProcessedFiles, nil
}

// discoverAllGradleProjects finds all Gradle files recursively for --all-projects.
// Uses simple discovery with runtime deduplication to avoid complex filtering logic.
func (p Plugin) discoverAllGradleProjects(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]discovery.FindResult, error) {
	// Find all Gradle files recursively (build files and settings files)
	findOpts := []discovery.FindOption{
		discovery.WithInclude("build.gradle"),
		discovery.WithInclude("build.gradle.kts"),
		discovery.WithInclude("settings.gradle"),
		discovery.WithInclude("settings.gradle.kts"),
		discovery.WithCommonExcludes(),
	}

	if len(options.Global.Exclude) > 0 {
		findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find gradle files: %w", err)
	}
	return files, nil
}

// convertProjects maps every gradleProject from the parsed JSON into an
// SCAResult, optionally filtering by --gradle-sub-project.
//
// dir is the original scan root used to compute relative target file paths,
// matching the behavior of the legacy snyk-gradle-plugin in --all-sub-projects
// mode where each project's targetFile is path.relative(root, absoluteBuildFile).
func (p Plugin) convertProjects(
	ctx context.Context,
	log logger.Logger,
	parsed *dependencyGraphJSON,
	dir string,
	discoveredBuildFile string,
	options *ecosystems.SCAPluginOptions,
) (results []ecosystems.SCAResult, processedFiles []string) {
	subProject := options.Gradle.SubProject

	// Convert target file to absolute path for comparison when filtering
	var targetFileAbs string
	if options.Global.TargetFile != nil {
		if filepath.IsAbs(*options.Global.TargetFile) {
			targetFileAbs = *options.Global.TargetFile
		} else {
			targetFileAbs = filepath.Join(dir, *options.Global.TargetFile)
		}
	}

	// Iterate projects in Gradle evaluation order (preserved by the array format).
	// The init script outputs projects via root.allprojects.each, which visits
	// in evaluation order: root first, then subprojects in settings.gradle
	// declaration order.
	for _, proj := range parsed.Projects {
		// Apply --gradle-sub-project filter when specified.
		if subProject != "" && !matchesSubProject(proj.Path, proj.Name, subProject) {
			continue
		}

		// Apply --target-file filter when specified.
		// Only return the project whose build file matches the target file.
		if targetFileAbs != "" {
			absFile := proj.BuildFile
			if absFile == "" {
				absFile = discoveredBuildFile
			}
			if absFile != targetFileAbs {
				continue
			}
		}

		// Gradle reports each project's build file as an absolute path.
		// Convert it to a path relative to the scan root (dir) so that the
		// result matches what the legacy snyk-gradle-plugin returns.
		absFile := proj.BuildFile
		if absFile == "" {
			absFile = discoveredBuildFile
		}
		relFile := relativeTargetFile(dir, absFile)

		depGraph, err := buildDepGraph(&proj)
		if err != nil {
			log.Error(ctx, "Failed to build dep graph for Gradle project",
				logger.Attr("project_path", proj.Path),
				logger.Err(err))
			results = append(results, ecosystems.SCAResult{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						ProjectType: "gradle",
						TargetFile:  &relFile,
					},
				},
				Error: err,
			})

			continue
		}

		log.Debug(ctx, "Built dep graph for Gradle project",
			logger.Attr("project_path", proj.Path))

		var rootName string
		if rootPkg := depGraph.GetRootPkg(); rootPkg != nil {
			rootName = rootPkg.Info.Name
		}

		results = append(results, ecosystems.SCAResult{
			DepGraph: depGraph,
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType:       "gradle",
					TargetFile:        &relFile,
					RootComponentName: rootName,
				},
			},
		})
		processedFiles = append(processedFiles, relFile)
	}

	return results, processedFiles
}

// relativeTargetFile returns absFile as a path relative to dir.
// If filepath.Rel fails (e.g. different volumes on Windows), absFile is returned as-is.
func relativeTargetFile(dir, absFile string) string {
	rel, err := filepath.Rel(dir, absFile)
	if err != nil {
		return absFile
	}

	return rel
}

// resolveInitScript writes the embedded Snyk init script to a temp file.
// This script is always required for dependency graph generation.
// Additional user init scripts should be handled via --init-script flags in buildExtraArgs.
func resolveInitScript() (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "snyk-deps-init-*.gradle")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp init script: %w", err)
	}

	if _, err := f.Write(embeddedInitScript); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", nil, fmt.Errorf("failed to write temp init script: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", nil, fmt.Errorf("failed to close temp init script: %w", err)
	}

	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

// buildExtraArgs assembles any additional Gradle command-line arguments derived
// from plugin options (e.g. user-provided init scripts, configuration flags).
func buildExtraArgs(projectDir string, options *ecosystems.SCAPluginOptions) ([]string, error) {
	var args []string

	// Add user-provided init script as an additional --init-script flag.
	// The embedded Snyk init script is always used; this allows users to provide
	// supplementary init scripts needed to make their Gradle build work.
	if userInitScript := options.Gradle.InitScript; userInitScript != "" {
		// Resolve relative paths against the project directory
		initPath := userInitScript
		if !filepath.IsAbs(userInitScript) {
			initPath = filepath.Join(projectDir, userInitScript)
		}

		// Defensive validation: ensure the init script exists and is a file
		info, err := os.Stat(initPath)
		if err != nil {
			return nil, fmt.Errorf("user init script not found: %s: %w", userInitScript, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("user init script is a directory, not a file: %s", userInitScript)
		}

		args = append(args, "--init-script", initPath)
	}

	// Reserved for future flag forwarding (e.g. --configuration, -P flags).
	return args, nil
}

// isBuildFile reports whether path refers to a Gradle build file.
func isBuildFile(path string) bool {
	name := filepath.Base(path)
	return name == "build.gradle" || name == "build.gradle.kts"
}

// isSettingsFile reports whether path refers to a Gradle settings file.
func isSettingsFile(path string) bool {
	name := filepath.Base(path)
	return name == "settings.gradle" || name == "settings.gradle.kts"
}

// matchesSubProject returns true when the Gradle project path or name matches
// the requested sub-project selector.
func matchesSubProject(projPath, projName, selector string) bool {
	return projPath == selector ||
		projName == selector ||
		projPath == ":"+selector ||
		projPath == selector+":"
}

// gradleErrorResult wraps a gradle execution error in an SCAResult so the
// caller can surface it as a warning rather than a hard failure.
// The target file is expressed relative to dir (the original scan root).
func gradleErrorResult(dir, buildFilePath string, err error) ecosystems.SCAResult {
	buildFile := relativeTargetFile(dir, buildFilePath)
	return ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType: "gradle",
				TargetFile:  &buildFile,
			},
		},
		Error: err,
	}
}
