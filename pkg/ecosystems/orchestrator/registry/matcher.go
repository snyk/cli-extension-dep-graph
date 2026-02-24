package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
)

// PluginMatch represents a plugin matched to a set of files.
type PluginMatch struct {
	Plugin     ecosystems.SCAPlugin
	TargetFile string // The primary manifest file that triggered the match
}

// MatchPluginsToFiles discovers files in a directory and matches them to registered plugins.
// Returns a list of plugin matches based on file discovery and plugin capabilities.
func MatchPluginsToFiles(ctx context.Context, registry *Registry, rootDir string, findOpts []discovery.FindOption) ([]PluginMatch, error) {
	// Discover all manifest files in the directory
	allPlugins := registry.AllPlugins()
	if len(allPlugins) == 0 {
		return []PluginMatch{}, nil
	}

	// Collect all primary manifests from all plugins
	manifestPatterns := make(map[string]bool)
	for _, plugin := range allPlugins {
		for _, manifest := range plugin.Capability().PrimaryManifests {
			manifestPatterns[manifest] = true
		}
	}

	// Build discovery options to find all potential manifest files
	var discoveryOpts []discovery.FindOption
	discoveryOpts = append(discoveryOpts, findOpts...)
	for manifest := range manifestPatterns {
		discoveryOpts = append(discoveryOpts, discovery.WithInclude(manifest))
	}

	// Discover files
	files, err := discovery.FindFiles(ctx, rootDir, discoveryOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to discover files: %w", err)
	}

	if len(files) == 0 {
		return []PluginMatch{}, nil
	}

	// Group files by directory
	filesByDir := groupFilesByDirectory(files)

	// Match plugins to files
	var matches []PluginMatch
	for dir, dirFiles := range filesByDir {
		pluginMatches := matchPluginsInDirectory(allPlugins, dir, dirFiles)
		matches = append(matches, pluginMatches...)
	}

	return matches, nil
}

// groupFilesByDirectory groups discovered files by their parent directory.
func groupFilesByDirectory(files []discovery.FindResult) map[string][]discovery.FindResult {
	filesByDir := make(map[string][]discovery.FindResult)
	for _, file := range files {
		dir := filepath.Dir(file.Path)
		filesByDir[dir] = append(filesByDir[dir], file)
	}
	return filesByDir
}

// matchPluginsInDirectory matches plugins to files within a single directory.
func matchPluginsInDirectory(plugins []ecosystems.SCAPlugin, dir string, files []discovery.FindResult) []PluginMatch {
	// Create a map of filenames in this directory for quick lookup
	fileNames := make(map[string]discovery.FindResult)
	for _, file := range files {
		fileName := filepath.Base(file.Path)
		fileNames[fileName] = file
	}

	var matches []PluginMatch

	// For each file, find the best matching plugin
	for fileName, file := range fileNames {
		bestMatch := findBestPluginForFile(plugins, fileName, dir, fileNames)
		if bestMatch != nil {
			matches = append(matches, PluginMatch{
				Plugin:     bestMatch,
				TargetFile: file.RelPath,
			})
		}
	}

	return matches
}

// findBestPluginForFile finds the most specific plugin that can handle a given file.
// Returns nil if no plugin matches.
func findBestPluginForFile(plugins []ecosystems.SCAPlugin, fileName string, dir string, availableFiles map[string]discovery.FindResult) ecosystems.SCAPlugin {
	var bestMatch ecosystems.SCAPlugin
	bestSpecificity := -1

	for _, plugin := range plugins {
		capability := plugin.Capability()

		// Check if this plugin handles this file as a primary manifest
		isPrimary := false
		for _, manifest := range capability.PrimaryManifests {
			if manifest == fileName {
				isPrimary = true
				break
			}
		}

		if !isPrimary {
			continue
		}

		// Check if all required companions are present
		allCompanionsPresent := true
		for _, companion := range capability.RequiredCompanions {
			companionPath := filepath.Join(dir, companion)
			if _, err := os.Stat(companionPath); os.IsNotExist(err) {
				allCompanionsPresent = false
				break
			}
		}

		if !allCompanionsPresent {
			continue
		}

		// Calculate specificity (number of required companions)
		specificity := len(capability.RequiredCompanions)

		// Select plugin with highest specificity
		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestMatch = plugin
		}
	}

	return bestMatch
}

// BuildDiscoveryOptions creates discovery options based on the SCAPluginOptions configuration.
func BuildDiscoveryOptions(options *ecosystems.SCAPluginOptions) []discovery.FindOption {
	var findOpts []discovery.FindOption

	switch {
	case options.Global.TargetFile != nil:
		// Use specific target file if provided
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(*options.Global.TargetFile),
		}
	case options.Global.AllProjects:
		// Find all manifest files recursively with common exclusions
		findOpts = []discovery.FindOption{
			discovery.WithCommonExcludes(),
		}
	default:
		// Default: find manifest files at root only (no recursive search)
		// This will be combined with manifest patterns in MatchPluginsToFiles
		findOpts = []discovery.FindOption{}
	}

	return findOpts
}
