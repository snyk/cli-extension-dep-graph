package bun

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// WhyGraph holds the parsed output of `bun why "*"`.
type WhyGraph struct {
	// AllPkgs maps bare package name to resolved version.
	AllPkgs map[string]string
	// ReverseAdj maps "pkg@ver" to the set of direct-dependent node IDs that require it.
	ReverseAdj map[string]map[string]struct{}
}

// ParseWhyOutput parses the text output of `bun why "*"` into a WhyGraph.
//
// The output format is a reverse dependency tree: each root entry shows what depends
// on that package. We only extract depth-1 children (direct dependents) because every
// package has its own root block, making deeper levels redundant.
func ParseWhyOutput(data []byte) (*WhyGraph, error) {
	graph := &WhyGraph{
		AllPkgs:    make(map[string]string),
		ReverseAdj: make(map[string]map[string]struct{}),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var currentRoot string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			continue
		}

		// Root entry: no leading whitespace; format is "name@version".
		if line[0] != ' ' && line[0] != '\t' {
			name, version := parseNameVersion(strings.TrimSpace(line))
			if version != defaultVersion {
				currentRoot = nodeIDFor(name, version)
				graph.AllPkgs[name] = version

				if _, ok := graph.ReverseAdj[currentRoot]; !ok {
					graph.ReverseAdj[currentRoot] = make(map[string]struct{})
				}
			}

			continue
		}

		// Depth-1 line: starts with "  └─ " or "  ├─ ".
		if currentRoot == "" {
			continue
		}

		content, ok := extractDepth1Content(line)
		if !ok {
			continue
		}

		dep := extractPackageRef(content)
		if dep != "" {
			graph.ReverseAdj[currentRoot][dep] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parsing bun why output: %w", err)
	}

	return graph, nil
}

// depth1Prefixes are the two possible depth-1 line prefixes.
var depth1Prefixes = []string{"  └─ ", "  ├─ "}

// extractDepth1Content returns the content after the depth-1 tree prefix, if present.
func extractDepth1Content(line string) (string, bool) {
	for _, prefix := range depth1Prefixes {
		if strings.HasPrefix(line, prefix) {
			return line[len(prefix):], true
		}
	}

	return "", false
}

// extractPackageRef extracts the "name@version" ref from depth-1 content.
// Returns an empty string for root-project leaf entries (which have no version).
func extractPackageRef(content string) string {
	// Strip optional "peer " annotation.
	rest := strings.TrimPrefix(content, "peer ")

	// Strip " (requires ...)" suffix.
	if i := strings.Index(rest, " (requires "); i >= 0 {
		rest = rest[:i]
	}

	rest = strings.TrimSpace(rest)

	// Root project leaves appear without a resolved version: "pkg-name (requires ...)".
	// Detect by checking whether there is a "@" after position 0.
	if strings.LastIndex(rest, "@") <= 0 {
		return ""
	}

	return rest
}
