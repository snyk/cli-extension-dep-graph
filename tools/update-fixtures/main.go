package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
)

func main() {
	flag.Parse()

	fixturesDir := filepath.Join("pkg", "ecosystems", "testdata", "fixtures", "python")
	if _, err := os.Stat(fixturesDir); os.IsNotExist(err) {
		fmt.Printf("Error: Fixtures directory not found: %s\n", fixturesDir)
		os.Exit(1)
	}

	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		fmt.Printf("Error reading fixtures directory: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			fixturePath := filepath.Join(fixturesDir, entry.Name())
			if err := updateFixture(fixturePath); err != nil {
				fmt.Printf("Error processing %s: %v\n", entry.Name(), err)
			}
		}
	}

	fmt.Println("\nDone!")
}

func updateFixture(fixturePath string) error {
	fixtureName := filepath.Base(fixturePath)
	fmt.Printf("\nProcessing fixture: %s\n", fixtureName)

	requirementsPath := filepath.Join(fixturePath, "requirements.txt")
	if _, err := os.Stat(requirementsPath); os.IsNotExist(err) {
		fmt.Println("  Skipping: no requirements.txt found")
		return nil
	}

	// Get the current Python version
	currentPythonVersion, err := getCurrentPythonVersion()
	if err != nil {
		return fmt.Errorf("failed to detect Python version: %w", err)
	}
	fmt.Printf("  Detected Python version: %s\n", currentPythonVersion)

	// Auto-detect from existing files
	existingVersions := detectPythonVersions(fixturePath)
	
	// Only generate for the current Python version
	// Check if we need version-specific files
	var versions []string
	if len(existingVersions) > 1 || (len(existingVersions) == 1 && existingVersions[0] != "3.14") {
		// Version-specific files exist
		versions = []string{currentPythonVersion}
		
		// Warn if other versions exist
		for _, v := range existingVersions {
			if v != currentPythonVersion {
				fmt.Printf("  Warning: Fixture has version-specific file for Python %s but current Python is %s\n", v, currentPythonVersion)
				fmt.Printf("           Run this script with Python %s to update that fixture\n", v)
			}
		}
	} else {
		// Only generic expected_plugin.json exists (assumed to be 3.14)
		// Only update if current Python is 3.14
		if currentPythonVersion == "3.14" {
			versions = []string{"3.14"}
		} else {
			fmt.Printf("  Skipping: expected_plugin.json assumes Python 3.14 but current Python is %s\n", currentPythonVersion)
			return nil
		}
	}

	for _, pyVersion := range versions {
		if pyVersion != currentPythonVersion {
			fmt.Printf("  Skipping Python %s (current Python is %s)\n", pyVersion, currentPythonVersion)
			fmt.Printf("  To update this fixture, run the script with Python %s installed\n", pyVersion)
			continue
		}
		
		fmt.Printf("  Generating expected output for Python %s...\n", pyVersion)
		if err := generateExpectedOutput(fixturePath, pyVersion); err != nil {
			fmt.Printf("    Warning: Could not generate output for Python %s: %v\n", pyVersion, err)
			continue
		}
	}

	return nil
}

func getCurrentPythonVersion() (string, error) {
	// Use the pip plugin's GetPythonVersion function
	fullVersion, err := pip.GetPythonVersion()
	if err != nil {
		return "", err
	}

	// Parse to major.minor (e.g., "3.14.1" -> "3.14")
	parts := strings.Split(fullVersion, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid Python version format: %s", fullVersion)
	}

	return fmt.Sprintf("%s.%s", parts[0], parts[1]), nil
}

func detectPythonVersions(fixturePath string) []string {
	versionPattern := regexp.MustCompile(`expected_plugin_(\d+\.\d+)\.json`)
	versions := make(map[string]bool)

	entries, err := os.ReadDir(fixturePath)
	if err != nil {
		return []string{"3.14"}
	}

	for _, entry := range entries {
		if matches := versionPattern.FindStringSubmatch(entry.Name()); matches != nil {
			versions[matches[1]] = true
		}
	}

	if len(versions) == 0 {
		return []string{"3.14"}
	}

	result := make([]string, 0, len(versions))
	for v := range versions {
		result = append(result, v)
	}
	return result
}

func generateExpectedOutput(fixturePath, pythonVersion string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Determine output path based on existing files
	var outputPath string
	
	// First, check if a version-specific file exists for the current Python version
	versionSpecificPath := filepath.Join(fixturePath, fmt.Sprintf("expected_plugin_%s.json", pythonVersion))
	genericPath := filepath.Join(fixturePath, "expected_plugin.json")
	
	if _, err := os.Stat(versionSpecificPath); err == nil {
		// Version-specific file exists for this Python version, use it
		outputPath = versionSpecificPath
	} else if _, err := os.Stat(genericPath); err == nil {
		// Generic file exists, use it (assumed to be for 3.14)
		outputPath = genericPath
	} else {
		// No existing file found, create version-specific file
		outputPath = versionSpecificPath
	}

	// Read existing expected output to preserve runtime field
	var existingResults []ecosystems.SCAResult
	if existingData, err := os.ReadFile(outputPath); err == nil {
		if err := json.Unmarshal(existingData, &existingResults); err != nil {
			fmt.Printf("    Warning: Could not parse existing output file: %v\n", err)
		}
	}

	plugin := pip.Plugin{}
	options := ecosystems.NewPluginOptions()
	// Enable AllProjects to find all requirements.txt files recursively
	// This is needed for fixtures like multi-requirements that have multiple requirements files
	options.Global.AllProjects = true

	results, err := plugin.BuildDepGraphsFromDir(ctx, logger.Nop(), fixturePath, options)
	if err != nil {
		return fmt.Errorf("failed to build dependency graph: %w", err)
	}

	if len(results) == 0 {
		return fmt.Errorf("no results generated")
	}

	fmt.Printf("    Generated %d dependency graph(s)\n", len(results))
	for i, result := range results {
		if result.Error != nil {
			fmt.Printf("      [%d] %s - ERROR: %v\n", i, result.Metadata.TargetFile, result.Error)
		} else {
			fmt.Printf("      [%d] %s - OK\n", i, result.Metadata.TargetFile)
		}
	}

	// Check if all results have errors
	allHaveErrors := true
	for _, result := range results {
		if result.Error == nil {
			allHaveErrors = false
			break
		}
	}
	
	if allHaveErrors {
		return fmt.Errorf("all results contain errors: %w", results[0].Error)
	}

	// Preserve runtime from existing results if available
	for i := range results {
		results[i].Error = nil
		if i < len(existingResults) && existingResults[i].Metadata.Runtime != "" {
			results[i].Metadata.Runtime = existingResults[i].Metadata.Runtime
		}
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("    Updated %s\n", filepath.Base(outputPath))
	return nil
}
