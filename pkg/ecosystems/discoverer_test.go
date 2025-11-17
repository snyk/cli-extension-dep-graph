package ecosystems

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestDiscoverer_Discover(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir := t.TempDir()

	// Create test directory structure:
	// tempDir/
	//   pom.xml                    (maven project at root)
	//   project1/
	//     package.json             (npm project)
	//     package-lock.json
	//   project2/
	//     build.gradle             (gradle project)
	//     settings.gradle
	//   nested/
	//     deep/
	//       pom.xml                (maven project, depth 2)
	//   node_modules/
	//     dependency/
	//       package.json           (should be excluded)
	//   .git/
	//     config                   (should be excluded)

	testFiles := map[string]string{
		"pom.xml":                              "<project></project>",
		"project1/package.json":                "{}",
		"project1/package-lock.json":           "{}",
		"project2/build.gradle":                "",
		"project2/settings.gradle":             "",
		"nested/deep/pom.xml":                  "<project></project>",
		"node_modules/dependency/package.json": "{}",
		".git/config":                          "",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tempDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	tests := []struct {
		name               string
		options            DiscovererOptions
		expectedProjectLen int
		expectedProjects   map[string][]string // project type -> list of root dirs (relative to tempDir)
	}{
		{
			name: "discover maven projects at depth 0",
			options: DiscovererOptions{
				SearchDir: tempDir,
				MaxDepth:  0,
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "maven",
						RequiredFiles: []string{"pom.xml"},
					},
				},
			},
			expectedProjectLen: 1,
			expectedProjects: map[string][]string{
				"maven": {"."},
			},
		},
		{
			name: "discover npm projects with optional lock file",
			options: DiscovererOptions{
				SearchDir: tempDir,
				MaxDepth:  1,
				Exclude:   []string{"node_modules", ".git"},
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "npm",
						RequiredFiles: []string{"package.json"},
						OptionalFiles: []string{"package-lock.json"},
					},
				},
			},
			expectedProjectLen: 1,
			expectedProjects: map[string][]string{
				"npm": {"project1"},
			},
		},
		{
			name: "discover gradle projects with glob patterns",
			options: DiscovererOptions{
				SearchDir: tempDir,
				MaxDepth:  1,
				Exclude:   []string{"node_modules", ".git"},
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "gradle",
						RequiredFiles: []string{"build.gradle"},
						OptionalFiles: []string{"*.gradle"},
					},
				},
			},
			expectedProjectLen: 1,
			expectedProjects: map[string][]string{
				"gradle": {"project2"},
			},
		},
		{
			name: "discover all projects with depth -1 (unlimited)",
			options: DiscovererOptions{
				SearchDir: tempDir,
				MaxDepth:  -1,
				Exclude:   []string{"node_modules", ".git"},
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "maven",
						RequiredFiles: []string{"pom.xml"},
					},
					{
						Name:          "npm",
						RequiredFiles: []string{"package.json"},
						OptionalFiles: []string{"package-lock.json"},
					},
					{
						Name:          "gradle",
						RequiredFiles: []string{"build.gradle"},
					},
				},
			},
			expectedProjectLen: 4,
			expectedProjects: map[string][]string{
				"maven":  {".", "nested/deep"},
				"npm":    {"project1"},
				"gradle": {"project2"},
			},
		},
		{
			name: "discover with max depth 2",
			options: DiscovererOptions{
				SearchDir: tempDir,
				MaxDepth:  2,
				Exclude:   []string{"node_modules", ".git"},
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "maven",
						RequiredFiles: []string{"pom.xml"},
					},
				},
			},
			expectedProjectLen: 2,
			expectedProjects: map[string][]string{
				"maven": {".", "nested/deep"},
			},
		},
		{
			name: "exclude files by glob pattern",
			options: DiscovererOptions{
				SearchDir: tempDir,
				MaxDepth:  1,
				Exclude:   []string{"node_modules", ".git", "package-lock.json"},
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "npm",
						RequiredFiles: []string{"package.json"},
						OptionalFiles: []string{"package-lock.json"},
					},
				},
			},
			expectedProjectLen: 1,
			expectedProjects: map[string][]string{
				"npm": {"project1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discoverer := NewDiscoverer(tt.options)
			projects, err := discoverer.Discover()
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			if len(projects) != tt.expectedProjectLen {
				t.Errorf("Expected %d projects, got %d", tt.expectedProjectLen, len(projects))
				for i, p := range projects {
					relPath, _ := filepath.Rel(tempDir, p.RootDir)
					t.Logf("Project %d: Type=%s, RootDir=%s, Required=%v, Optional=%v",
						i, p.Type, relPath, p.RequiredFiles, p.OptionalFiles)
				}
			}

			// Verify expected projects
			foundProjects := make(map[string][]string)
			for _, project := range projects {
				relPath, err := filepath.Rel(tempDir, project.RootDir)
				if err != nil {
					t.Fatalf("Failed to get relative path: %v", err)
				}
				foundProjects[project.Type] = append(foundProjects[project.Type], relPath)
			}

			// Sort for consistent comparison
			for _, paths := range foundProjects {
				sort.Strings(paths)
			}
			for _, paths := range tt.expectedProjects {
				sort.Strings(paths)
			}

			for projType, expectedPaths := range tt.expectedProjects {
				foundPaths, ok := foundProjects[projType]
				if !ok {
					t.Errorf("Expected to find %s projects, but none were found", projType)
					continue
				}

				if len(foundPaths) != len(expectedPaths) {
					t.Errorf("Expected %d %s projects, got %d: expected=%v, found=%v",
						len(expectedPaths), projType, len(foundPaths), expectedPaths, foundPaths)
					continue
				}

				for i, expectedPath := range expectedPaths {
					if foundPaths[i] != expectedPath {
						t.Errorf("Expected %s project at %s, got %s", projType, expectedPath, foundPaths[i])
					}
				}
			}
		})
	}
}

func TestDiscoverer_DiscoverWithOptionalFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create npm project with only package.json
	testFiles := map[string]string{
		"project1/package.json":      "{}",
		"project1/package-lock.json": "{}",
		"project2/package.json":      "{}",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tempDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	discoverer := NewDiscoverer(DiscovererOptions{
		SearchDir: tempDir,
		MaxDepth:  1,
		ProjectDefinitions: []ProjectDefinition{
			{
				Name:          "npm",
				RequiredFiles: []string{"package.json"},
				OptionalFiles: []string{"package-lock.json", "yarn.lock"},
			},
		},
	})

	projects, err := discoverer.Discover()
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(projects) != 2 {
		t.Fatalf("Expected 2 projects, got %d", len(projects))
	}

	// Sort projects by root dir for consistent comparison
	sort.Slice(projects, func(i, j int) bool {
		return projects[i].RootDir < projects[j].RootDir
	})

	// Check project1 has both required and optional files
	project1 := projects[0]
	if len(project1.RequiredFiles) != 1 || project1.RequiredFiles[0] != "package.json" {
		t.Errorf("Project1: expected required file 'package.json', got %v", project1.RequiredFiles)
	}
	if len(project1.OptionalFiles) != 1 || project1.OptionalFiles[0] != "package-lock.json" {
		t.Errorf("Project1: expected optional file 'package-lock.json', got %v", project1.OptionalFiles)
	}

	// Check project2 has only required files (no optional)
	project2 := projects[1]
	if len(project2.RequiredFiles) != 1 || project2.RequiredFiles[0] != "package.json" {
		t.Errorf("Project2: expected required file 'package.json', got %v", project2.RequiredFiles)
	}
	if len(project2.OptionalFiles) != 0 {
		t.Errorf("Project2: expected no optional files, got %v", project2.OptionalFiles)
	}
}

func TestDiscoverer_InvalidSearchDir(t *testing.T) {
	discoverer := NewDiscoverer(DiscovererOptions{
		SearchDir: "/non/existent/path",
		MaxDepth:  0,
		ProjectDefinitions: []ProjectDefinition{
			{
				Name:          "test",
				RequiredFiles: []string{"test.txt"},
			},
		},
	})

	_, err := discoverer.Discover()
	if err == nil {
		t.Error("Expected error for non-existent directory, got nil")
	}
}

func TestDiscoverer_FileAsSearchDir(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	discoverer := NewDiscoverer(DiscovererOptions{
		SearchDir: testFile,
		MaxDepth:  0,
		ProjectDefinitions: []ProjectDefinition{
			{
				Name:          "test",
				RequiredFiles: []string{"test.txt"},
			},
		},
	})

	_, err := discoverer.Discover()
	if err == nil {
		t.Error("Expected error when search dir is a file, got nil")
	}
}

func TestDiscoveredProject_AllFiles(t *testing.T) {
	project := DiscoveredProject{
		Type:          "test",
		RootDir:       "/test",
		RequiredFiles: []string{"file1.txt", "file2.txt"},
		OptionalFiles: []string{"file3.txt"},
	}

	allFiles := project.AllFiles()
	if len(allFiles) != 3 {
		t.Errorf("Expected 3 files, got %d", len(allFiles))
	}

	expected := []string{"file1.txt", "file2.txt", "file3.txt"}
	for i, expectedFile := range expected {
		if allFiles[i] != expectedFile {
			t.Errorf("Expected file %s at index %d, got %s", expectedFile, i, allFiles[i])
		}
	}
}

func TestDiscoverer_TargetFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create multiple project types
	testFiles := map[string]string{
		"frontend/package.json":      "{}",
		"frontend/package-lock.json": "{}",
		"backend/pom.xml":            "<project></project>",
		"backend/requirements.txt":   "flask==2.0.0",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tempDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	tests := []struct {
		name               string
		targetFile         *string
		expectedProjectLen int
		expectedTypes      []string
	}{
		{
			name:               "no target file - find all projects",
			targetFile:         nil,
			expectedProjectLen: 3, // npm, maven, pip
			expectedTypes:      []string{"npm", "maven", "pip"},
		},
		{
			name:               "target file package.json - only npm",
			targetFile:         stringPtr("package.json"),
			expectedProjectLen: 1,
			expectedTypes:      []string{"npm"},
		},
		{
			name:               "target file pom.xml - only maven",
			targetFile:         stringPtr("pom.xml"),
			expectedProjectLen: 1,
			expectedTypes:      []string{"maven"},
		},
		{
			name:               "target file requirements.txt - only pip",
			targetFile:         stringPtr("requirements.txt"),
			expectedProjectLen: 1,
			expectedTypes:      []string{"pip"},
		},
		{
			name:               "target file package-lock.json - only npm (optional file)",
			targetFile:         stringPtr("package-lock.json"),
			expectedProjectLen: 1,
			expectedTypes:      []string{"npm"},
		},
		{
			name:               "target file nonexistent.txt - no projects",
			targetFile:         stringPtr("nonexistent.txt"),
			expectedProjectLen: 0,
			expectedTypes:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discoverer := NewDiscoverer(DiscovererOptions{
				SearchDir:  tempDir,
				MaxDepth:   -1,
				TargetFile: tt.targetFile,
				ProjectDefinitions: []ProjectDefinition{
					{
						Name:          "npm",
						RequiredFiles: []string{"package.json"},
						OptionalFiles: []string{"package-lock.json"},
					},
					{
						Name:          "maven",
						RequiredFiles: []string{"pom.xml"},
					},
					{
						Name:          "pip",
						RequiredFiles: []string{"requirements.txt"},
					},
				},
			})

			projects, err := discoverer.Discover()
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			if len(projects) != tt.expectedProjectLen {
				t.Errorf("Expected %d projects, got %d", tt.expectedProjectLen, len(projects))
			}

			// Check project types
			foundTypes := make(map[string]bool)
			for _, project := range projects {
				foundTypes[project.Type] = true
			}

			for _, expectedType := range tt.expectedTypes {
				if !foundTypes[expectedType] {
					t.Errorf("Expected to find project type %s, but it was not found", expectedType)
				}
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
