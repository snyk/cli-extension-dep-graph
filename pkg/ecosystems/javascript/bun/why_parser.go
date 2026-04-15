package bun

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

var (
	// rootLineRe matches a package header line (no leading whitespace).
	//
	// Group 1: package name (may be scoped, e.g. "@types/node").
	// Group 2: resolved version (empty string marks the root project placeholder).
	//
	// Examples:
	//   "debug@4.4.3"                                      → ["debug", "4.4.3"]
	//   "@types/node@25.5.2"                               → ["@types/node", "25.5.2"]
	//   "@workspace/logger@workspace:packages/logger"       → ["@workspace/logger", "workspace:packages/logger"]
	//   "my-app@"                                          → ["my-app", ""]  (root project, skipped)
	rootLineRe = regexp.MustCompile(`^(@?[^@\s]+)@(\S*)$`)

	// depth1LineRe matches a direct-dependent line produced by `bun why '*' --top`
	// where the dependent is a versioned package (not the root project).
	//
	// Format: "  [└├]─ [dev |peer |optional ]name@version[ (requires ...)]"
	//
	// Group 1: "name@version" of the dependent package.
	//   Root project references (e.g. "my-app (requires ^4)") have no version component,
	//   so they never match — they are caught by depth1RootRe instead.
	depth1LineRe = regexp.MustCompile(`^  [└├]─ (?:dev |peer |optional )?(@?[^@\s(]+@\S+?)(?:\s+\(requires[^)]+\))?$`)

	// depth1RootRe matches a depth-1 line where the dependent is the root project.
	// The dependent has no @version component — bun prints just the project name.
	//
	// Group 1: "dev " if this is a dev dependency; empty string otherwise.
	//
	// Examples (where "my-app" is the root):
	//   "  └─ my-app (requires ^4)"              → group 1: ""
	//   "  └─ dev my-app (requires latest)"      → group 1: "dev "
	//   "  └─ peer my-app (requires ^5)"         → group 1: ""  (peer treated as prod)
	//   "  └─ No dependents found"               → no match (contains spaces)
	depth1RootRe = regexp.MustCompile(`^  [└├]─ (dev )?(?:peer |optional )?(@?[^@\s(]+)(?:\s+\(requires[^)]+\))?$`)
)

// whyParser holds the mutable state accumulated while scanning `bun why '*' --top` output.
// Call parse to drive it over a reader and retrieve the completed whyOutput.
type whyParser struct {
	log         logger.Logger
	out         *whyOutput
	currentID   string
	currentLine string
	prodDeps    map[string]struct{}
	devDeps     map[string]struct{}
}

func (p *whyParser) recordVersionedPackageDependency(dependentID string) error {
	if p.currentID == "" {
		return fmt.Errorf("current package is unset, but found depth-1 line: %s", p.currentLine)
	}

	p.out.Graph[p.currentID][dependentID] = struct{}{}

	return nil
}

func (p *whyParser) recordRootPackageDependency(isDev bool) error {
	if p.currentID == "" {
		return fmt.Errorf("current package is unset, but found root-direct line: %s", p.currentLine)
	}

	if isDev {
		p.devDeps[p.currentID] = struct{}{}
	} else {
		p.prodDeps[p.currentID] = struct{}{}
	}

	return nil
}

func (p *whyParser) setCurrentPackage(match []string) {
	name, version := match[1], match[2]
	if version == "" {
		// Trailing "@" with no version marks the root project — reset.
		p.currentID = ""
		return
	}

	p.currentID = name + "@" + version
	p.out.Graph[p.currentID] = make(map[string]struct{})
}

// parse scans r line by line, updating the parser's state, and returns the
// completed whyOutput after applying workspace-version normalisation.
func (p *whyParser) parse(ctx context.Context, r io.Reader) (*whyOutput, error) {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		p.currentLine = scanner.Text()
		if p.currentLine == "" {
			continue
		}

		// Classify the line. The three regexes are anchored to mutually exclusive
		// prefixes ("  └─/├─" vs no leading whitespace), so at most one match is
		// non-nil.
		d1m := depth1LineRe.FindStringSubmatch(p.currentLine)  // "  └─ name@version [...]"
		d1rm := depth1RootRe.FindStringSubmatch(p.currentLine) // "  └─ [dev ]project-name [...]"
		rm := rootLineRe.FindStringSubmatch(p.currentLine)     // "name@version"

		matchCount := 0
		if d1m != nil {
			matchCount++
		}
		if d1rm != nil {
			matchCount++
		}
		if rm != nil {
			matchCount++
		}

		switch {
		case matchCount > 1:
			return nil, fmt.Errorf("ambiguous line matched %d regexes: %s", matchCount, p.currentLine)
		case rm != nil:
			p.setCurrentPackage(rm)
		case d1rm != nil:
			if err := p.recordRootPackageDependency(d1rm[1] == "dev "); err != nil {
				return nil, err
			}
		case d1m != nil:
			if err := p.recordVersionedPackageDependency(d1m[1]); err != nil {
				return nil, err
			}
		default:
			p.log.Warn(ctx, "Skipping unrecognized bun why output line", logger.Attr("line", p.currentLine))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning bun why output: %w", err)
	}

	// Workspace version normalisation post-pass.
	//
	// bun why truncates workspace versions in depth-1 lines: the root entry shows
	// "pkg@workspace:packages/x" but the dependent entry shows "pkg@workspace".
	// The truncated form can arrive before the canonical root line (bun outputs
	// alphabetically), so the fix must run as a post-pass once all canonical IDs
	// are known.
	for id := range p.out.Graph {
		normaliseWorkspaceSet(p.out.Graph[id], p.out.Graph)
	}
	normaliseWorkspaceSet(p.prodDeps, p.out.Graph)
	normaliseWorkspaceSet(p.devDeps, p.out.Graph)

	p.out.ProdDeps = slices.Collect(maps.Keys(p.prodDeps))
	p.out.DevDeps = slices.Collect(maps.Keys(p.devDeps))

	return p.out, nil
}

// parseWhyOutput parses the text output of `bun why '*' --top` into a whyOutput.
// It reads from r as a stream, so the caller need not buffer the full output first.
//
// The output is a reverse-dependency tree: each root entry is a resolved package,
// and its depth-1 children are its direct dependents (parents). We record this
// reverse-adjacency directly. depth-1 lines referencing the root project (no @version)
// are used to populate ProdDeps and DevDeps rather than the Graph adjacency.
func parseWhyOutput(ctx context.Context, log logger.Logger, r io.Reader) (*whyOutput, error) {
	p := &whyParser{
		log:      log,
		out:      &whyOutput{Graph: make(reverseGraph)},
		prodDeps: make(map[string]struct{}),
		devDeps:  make(map[string]struct{}),
	}

	return p.parse(ctx, r)
}

// normaliseWorkspaceSet replaces truncated workspace IDs in s with their canonical
// forms found as keys in graph.
//
// bun why truncates workspace versions in depth-1 lines (e.g. "pkg@workspace") but
// the root entry for the same package uses the full path ("pkg@workspace:packages/x").
// When multiple canonical forms share the same prefix (unlikely but possible), we sort
// and pick the lexicographically smallest to ensure deterministic output.
func normaliseWorkspaceSet(s map[string]struct{}, graph reverseGraph) {
	// Collect replacements first; mutating s while iterating it is undefined behavior.
	type replacement struct{ old, new string }

	var replacements []replacement

	for id := range s {
		if _, exists := graph[id]; exists {
			continue
		}

		prefix := id + ":"

		var matches []string

		for canonical := range graph {
			if strings.HasPrefix(canonical, prefix) {
				matches = append(matches, canonical)
			}
		}

		if len(matches) == 0 {
			continue
		}

		slices.Sort(matches)
		replacements = append(replacements, replacement{old: id, new: matches[0]})
	}

	for _, r := range replacements {
		delete(s, r.old)
		s[r.new] = struct{}{}
	}
}
