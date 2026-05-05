package gradle

import (
	"encoding/json"
	"fmt"
	"io"
)

// dependencyGraphJSON is the top-level output produced by snyk-deps-init.gradle.
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
type gradleDep struct {
	ID           string      `json:"id"`
	Pruned       pruneReason `json:"pruned,omitempty"`
	Unresolved   bool        `json:"unresolved,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	Dependencies []gradleDep `json:"dependencies"`
}

// allDepEntry is a member of the flat allDependencies list.
type allDepEntry struct {
	ID string `json:"id"`
}

// parseDependencyGraphJSON deserialises the JSON file produced by snyk-deps-init.gradle.
func parseDependencyGraphJSON(reader io.Reader) (*dependencyGraphJSON, error) {
	var result dependencyGraphJSON
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse snyk-deps-init.gradle output: %w", err)
	}
	return &result, nil
}
