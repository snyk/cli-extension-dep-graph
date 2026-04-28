package gradle

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

//go:embed init/snyk-deps-init.gradle
var embeddedInitScript []byte

const (
	// logAttrProjectDir is the structured-log key used when logging the Gradle project directory.
	logAttrProjectDir = "project_dir"
	// defaultBuildFile is the conventional Gradle build file name.
	defaultBuildFile = "build.gradle"
)

// Plugin is the Gradle SCA plugin.  It has no exported fields; all
// configuration is passed through ecosystems.SCAPluginOptions at call time.
type Plugin struct{}

// Compile-time assertion that Plugin satisfies the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// NewPlugin constructs a Gradle plugin ready for use.
func NewPlugin() Plugin {
	return Plugin{}
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
//   - The Gradle invocation always uses --no-daemon, --no-parallel and the
//     recommended GRADLE_OPTS flags for predictable, isolated execution.
//   - The init script traverses all sub-projects automatically; each sub-project
//     yields one SCAResult.  Use --gradle-sub-project to filter to a single one.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	if log == nil {
		log = logger.Nop()
	}

	projectDir, err := p.resolveProjectDir(dir, options)
	if err != nil {
		return nil, fmt.Errorf("gradle: %w", err)
	}
	if projectDir == "" {
		log.Info(ctx, "No Gradle build file found, skipping", logger.Attr("dir", dir))
		return &ecosystems.PluginResult{}, nil
	}

	log.Debug(ctx, "Gradle project root resolved", logger.Attr(logAttrProjectDir, projectDir))

	initScriptPath, cleanup, err := resolveInitScript()
	if err != nil {
		return nil, fmt.Errorf("gradle: failed to prepare init script: %w", err)
	}
	defer cleanup()

	extraArgs, err := buildExtraArgs(projectDir, options)
	if err != nil {
		return nil, fmt.Errorf("gradle: %w", err)
	}
	gradleBinary, err := ResolveGradleBinary(projectDir, options.Gradle.SkipWrapper)
	if err != nil {
		log.Error(ctx, "Gradle binary resolution failed",
			logger.Attr(logAttrProjectDir, projectDir),
			logger.Err(err))
		errResult := gradleErrorResult(dir, projectDir, err)
		return &ecosystems.PluginResult{Results: []ecosystems.SCAResult{errResult}}, nil
	}

	log.Debug(ctx, "Running Gradle dependency resolution",
		logger.Attr(logAttrProjectDir, projectDir),
		logger.Attr("init_script", initScriptPath),
		logger.Attr("gradle_binary", gradleBinary))

	data, err := runInitScript(ctx, projectDir, gradleBinary, initScriptPath, extraArgs)
	if err != nil {
		log.Error(ctx, "Gradle execution failed",
			logger.Attr(logAttrProjectDir, projectDir),
			logger.Err(err))
		// Surface as an error result rather than a hard failure so the caller
		// can still fall back to the legacy CLI for other ecosystems.
		errResult := gradleErrorResult(dir, projectDir, err)
		return &ecosystems.PluginResult{Results: []ecosystems.SCAResult{errResult}}, nil
	}

	parsed, err := parseDependencyGraphJSON(data)
	if err != nil {
		return nil, fmt.Errorf("gradle: failed to parse init script output: %w", err)
	}

	results, processedFiles := p.convertProjects(ctx, log, parsed, dir, projectDir, options)

	return &ecosystems.PluginResult{
		Results:        results,
		ProcessedFiles: processedFiles,
	}, nil
}

// resolveProjectDir determines the Gradle project root to scan.
// Returns ("", nil) when no Gradle project is found.
func (p Plugin) resolveProjectDir(dir string, options *ecosystems.SCAPluginOptions) (string, error) {
	if options.Global.TargetFile != nil {
		tf := *options.Global.TargetFile
		if !isBuildFile(tf) {
			// --target-file refers to a non-Gradle file; nothing to do.
			return "", nil
		}
		absPath := tf
		if !filepath.IsAbs(tf) {
			absPath = filepath.Join(dir, tf)
		}
		if _, err := os.Stat(absPath); err != nil {
			return "", fmt.Errorf("target file %s not found: %w", tf, err)
		}

		return filepath.Dir(absPath), nil
	}

	// No target file — scan the top level of dir for a Gradle build file.
	for _, name := range []string{defaultBuildFile, "build.gradle.kts"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return dir, nil
		}
	}

	return "", nil
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
	projectDir string,
	options *ecosystems.SCAPluginOptions,
) (results []ecosystems.SCAResult, processedFiles []string) {
	subProject := options.Gradle.SubProject

	for projPath, proj := range parsed.Projects {
		// Apply --gradle-sub-project filter when specified.
		if subProject != "" && !matchesSubProject(projPath, proj.Name, subProject) {
			continue
		}

		// Gradle reports each project's build file as an absolute path.
		// Convert it to a path relative to the scan root (dir) so that the
		// result matches what the legacy snyk-gradle-plugin returns.
		absFile := proj.BuildFile
		if absFile == "" {
			absFile = filepath.Join(projectDir, defaultBuildFile)
		}
		relFile := relativeTargetFile(dir, absFile)

		depGraph, err := buildDepGraph(&proj)
		if err != nil {
			log.Error(ctx, "Failed to build dep graph for Gradle project",
				logger.Attr("project_path", projPath),
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
			logger.Attr("project_path", projPath))

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

		// Defensive validation: ensure the init script exists and is readable
		info, err := os.Stat(initPath)
		if err != nil {
			return nil, fmt.Errorf("user init script not found: %s: %w", userInitScript, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("user init script is a directory, not a file: %s", userInitScript)
		}

		// Test readability
		if _, err := os.Open(initPath); err != nil {
			return nil, fmt.Errorf("user init script cannot be read: %s: %w", userInitScript, err)
		}

		args = append(args, "--init-script", initPath)
	}

	// Reserved for future flag forwarding (e.g. --configuration, -P flags).
	return args, nil
}

// isBuildFile reports whether path refers to a Gradle build file.
func isBuildFile(path string) bool {
	name := filepath.Base(path)
	return name == defaultBuildFile || name == "build.gradle.kts"
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
func gradleErrorResult(dir, projectDir string, err error) ecosystems.SCAResult {
	buildFile := relativeTargetFile(dir, filepath.Join(projectDir, defaultBuildFile))
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
