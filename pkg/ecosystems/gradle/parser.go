package gradle

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// dependencyGraphJSON is the top-level output produced by snyk-deps-init.gradle.
// The file is NDJSON: line 1 is the metadata object, each subsequent line is one project.
type dependencyGraphJSON struct {
	Metadata struct {
		GradleVersion string `json:"gradleVersion"`
		JavaVersion   string `json:"javaVersion"`
		GeneratedAt   string `json:"generatedAt"`
		RootProject   struct {
			Name    string `json:"name"`
			Group   string `json:"group"`
			Version string `json:"version"`
			Path    string `json:"path"`
		} `json:"rootProject"`
	} `json:"metadata"`
	Projects []gradleProject `json:"projects"`
}

// gradleProject represents a single Gradle project (root or sub-project).
type gradleProject struct {
	Name           string         `json:"name"`
	Group          string         `json:"group"`
	Version        string         `json:"version"`
	Path           string         `json:"path"`
	GAV            string         `json:"gav"`
	BuildFile      string         `json:"buildFile"`
	Configurations []gradleConfig `json:"configurations"`
}

// gradleConfig represents one resolved Gradle configuration (e.g. runtimeClasspath).
type gradleConfig struct {
	Name            string        `json:"name"`
	Description     string        `json:"description"`
	Root            configRoot    `json:"root"`
	AllDependencies []allDepEntry `json:"allDependencies"`
	Error           string        `json:"error,omitempty"`
}

// configRoot is the root node of a resolved configuration tree.
type configRoot struct {
	ID           string      `json:"id"`
	Dependencies []gradleDep `json:"dependencies"`
}

// pruneReason indicates why a dependency node was pruned (elided) during tree construction.
type pruneReason string

const (
	pruneVisited pruneReason = "visited" // Node was already expanded elsewhere in this configuration
	pruneCycle   pruneReason = "cycle"   // Node creates a cycle (appears on current ancestor chain)
)

// Valid returns true if this pruneReason has a recognized value.
func (p pruneReason) Valid() bool {
	return p == pruneVisited || p == pruneCycle
}

// IsEmpty returns true if this pruneReason is empty (not pruned).
func (p pruneReason) IsEmpty() bool {
	return p == ""
}

// IsPruned returns true if this dependency was pruned for any reason.
func (p pruneReason) IsPruned() bool {
	return p != "" && p.Valid()
}

// gradleDep is one node in the resolved dependency tree.
//
// Constraint edges originate from platform BOMs, dependency locking, and
// explicit constraints {} blocks. They influence version selection but do not
// represent real artifact dependencies, and the init script always emits them
// as leaves (no Dependencies, no Pruned).
type gradleDep struct {
	ID           string      `json:"id"`
	Pruned       pruneReason `json:"pruned,omitempty"`
	Constraint   bool        `json:"constraint,omitempty"`
	Unresolved   bool        `json:"unresolved,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	Dependencies []gradleDep `json:"dependencies"`
}

// allDepEntry is a member of the flat allDependencies list.
type allDepEntry struct {
	ID       string `json:"id"`
	Checksum string `json:"checksum,omitempty"`
	Type     string `json:"type,omitempty"`
}

// parseDependencyGraphJSON deserialises the NDJSON file produced by snyk-deps-init.gradle.
// Line 1 is parsed as metadata; each subsequent non-blank line is parsed as a project.
func parseDependencyGraphJSON(reader io.Reader) (*dependencyGraphJSON, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024*1024) // 1GB max line size

	var result dependencyGraphJSON
	var recordsRead int

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		recordsRead++

		if recordsRead == 1 {
			if err := json.Unmarshal(line, &result.Metadata); err != nil {
				return nil, fmt.Errorf("failed to parse metadata line: %w", err)
			}
			continue
		}

		var proj gradleProject
		if err := json.Unmarshal(line, &proj); err != nil {
			return nil, fmt.Errorf("failed to parse project line %d: %w", recordsRead, err)
		}
		result.Projects = append(result.Projects, proj)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading NDJSON output: %w", err)
	}

	if recordsRead == 0 {
		return nil, fmt.Errorf("NDJSON output is empty")
	}

	return &result, nil
}
