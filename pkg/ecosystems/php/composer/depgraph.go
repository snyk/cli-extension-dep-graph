package composer

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "composer"

// depGraphResult pairs a built dep graph with the relative path to the
// composer.json that describes it (relative to the lockfile dir).
//
// The composer plugin does not yet emit per-workspace graphs (composer
// monorepo support, e.g. wikimedia/composer-merge-plugin, is rare in the
// audited fixture corpus) so this struct currently always holds the root
// project graph at "composer.json". The shape mirrors the npm plugin to
// keep workspace handling drop-in if it lands later.
type depGraphResult struct {
	graph              *godepgraph.DepGraph
	composerJSONRelDir string
}

// composerTreeLineRe matches one branch line of `composer show --tree`
// output and captures the package name and the version specifier.
//
// Composer's text-tree format (composer 2.x, --no-ansi):
//
//	guzzlehttp/guzzle 7.8.0 Guzzle is a PHP HTTP client library
//	├──ext-json *
//	├──guzzlehttp/promises ^2.0
//	│  ├──php >=7.2.5
//	└──ralouphie/getallheaders ^3.0
//	   └──php >=5.6
//
// Branch glyphs are `├──`, `└──`, `│  `, `   `. We strip those, leaving
// "<name> <spec>[ description...]" — name has no spaces (composer enforces
// vendor/package syntax or a single token for platform packages like
// `php` and `ext-*`), so the first space splits name from the rest. The
// rest's first whitespace-separated token is the version specifier.
var composerTreeLineRe = regexp.MustCompile(`^\s*(\S+)\s+(\S+)`)

// parseTreeOutput consumes the streaming output of
// `composer show --locked --tree` and returns the canonical
// parsedOutput intermediate. It is tolerant of:
//
//   - Blank lines (composer separates top-level subtrees with them).
//   - Warning lines composer occasionally emits to stdout when
//     `--no-interaction` is not enough (rare; logged-and-skipped).
//   - Repeated subtrees for the same package (composer prints each
//     top-level dependency separately, so the same transitive package may
//     appear under multiple roots — we merge their child edges into the
//     same graph entry).
//
// The parser tracks depth via the indent width preceding each `├──` /
// `└──` / `   ` glyph. Each branch line increases depth by one relative
// to the indent prefix; we maintain a stack of parent IDs so the child
// at depth N attaches to the node at depth N-1.
func parseTreeOutput(r io.Reader) (*parsedOutput, error) {
	out := newParsedOutput()
	scanner := bufio.NewScanner(r)
	// composer show --tree can produce large outputs for monorepos. Allow
	// up to 16MB per logical line, matching the yarn classic parser.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024)

	// stack holds the parent ID at each depth. stack[0] is implicitly the
	// root project (top-level subtree headers attach to it); deeper entries
	// are pushed/popped as we descend and unwind.
	var stack []string

	seenRoot := make(map[string]struct{})

	for scanner.Scan() {
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}

		depth, name, version, ok := parseTreeLine(raw)
		if !ok {
			// Lines we don't recognise (e.g. composer warnings, banners
			// from unrelated stderr leaks) are ignored to keep the parser
			// resilient to small format drifts across composer minor
			// versions.
			continue
		}

		id := pkgID(name, version)
		if _, ok := out.Graph[id]; !ok {
			out.Graph[id] = make(map[string]struct{})
		}

		if depth == 0 {
			// Top-level subtree header: this is a direct dep of the root
			// project. Deduplicate — composer 2.x may emit the same
			// top-level package twice when both a runtime and a dev path
			// resolve to it (rare, but observed in mixed lockfiles).
			if _, seen := seenRoot[id]; !seen {
				out.RootDeps = append(out.RootDeps, id)
				seenRoot[id] = struct{}{}
			}
			stack = stack[:0]
			stack = append(stack, id)
			continue
		}

		// Branch line at depth>=1: trim the stack to the parent's depth
		// and attach the child edge.
		if depth > len(stack) {
			// Composer should never skip a depth level, but if it does
			// (corrupt or unexpected output) we tolerate it by treating
			// the line as a sibling of the deepest known parent.
			depth = len(stack)
		}
		stack = stack[:depth]
		parentID := stack[depth-1]
		out.Graph[parentID][id] = struct{}{}
		stack = append(stack, id)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning composer show output: %w", err)
	}
	return out, nil
}

// parseTreeLine extracts depth, name, and version from one line of
// `composer show --tree` output.
//
// Composer prints depth using a 3-character glyph (`├──`, `└──`) preceded
// by `│  ` or `   ` indentations — one indent unit per depth level. We
// count those indent units; the first glyph itself is depth 1.
//
// A line without any glyph (i.e. the first byte is not whitespace and not
// a tree drawing rune) is a top-level subtree header at depth 0.
//
// Returns ok=false for lines that don't match the tree shape (banners,
// warnings, blank lines stripped by the caller).
func parseTreeLine(raw string) (depth int, name, version string, ok bool) {
	// Detect depth and strip the tree-drawing prefix.
	trimmed, depth := stripTreePrefix(raw)
	if trimmed == "" {
		return 0, "", "", false
	}

	m := composerTreeLineRe.FindStringSubmatch(trimmed)
	if m == nil {
		return 0, "", "", false
	}
	return depth, m[1], m[2], true
}

// stripTreePrefix consumes the leading tree-drawing characters of a
// `composer show --tree` line and returns the remainder plus the depth.
//
// Each indent unit is exactly 3 runes. The two possible indent units are:
//
//	"│  "   continuation through a vertical bar (parent has more siblings)
//	"   "   blank continuation (parent has no more siblings)
//
// The deepest indent unit is replaced by a glyph that opens a branch:
//
//	"├──"   middle child
//	"└──"   last child
//
// A line whose first rune is none of those is depth 0 (a top-level
// subtree header).
func stripTreePrefix(raw string) (string, int) {
	// Top-level lines start with a non-whitespace, non-glyph rune.
	if len(raw) == 0 {
		return "", 0
	}
	switch raw[0] {
	case ' ', '\t', 0xE2: // 0xE2 is the first byte of the UTF-8 sequence for │ ├ └
		// Tree-drawn line; fall through to depth detection.
	default:
		return raw, 0
	}

	depth := 0
	i := 0
	for i < len(raw) {
		// Each indent unit is one of:
		//   "│  "    (three runes; "│" is 3 bytes in UTF-8 + two spaces)
		//   "   "    (three spaces)
		//   "├──"    (three runes; each tree glyph is 3 bytes in UTF-8)
		//   "└──"    (three runes; each tree glyph is 3 bytes in UTF-8)
		// Detect by inspecting the next few bytes.
		if strings.HasPrefix(raw[i:], "├──") || strings.HasPrefix(raw[i:], "└──") {
			depth++
			i += len("├──")
			// After the branch glyph, the remainder is the payload.
			return raw[i:], depth
		}
		if strings.HasPrefix(raw[i:], "│  ") {
			depth++
			i += len("│  ")
			continue
		}
		if strings.HasPrefix(raw[i:], "   ") {
			depth++
			i += 3
			continue
		}
		// Not an indent unit and not a branch glyph — unknown prefix; bail.
		return strings.TrimLeft(raw, " \t"), 0
	}
	return "", depth
}

// pkgID returns the canonical "name@version" identifier composer assigns
// to a node in the dep graph.
//
// Composer version specifiers in `show --tree` output may be exact pins
// (`1.2.3`), semver ranges (`^2.0`, `>=1.0`), or `*` for unconstrained
// platform packages. We preserve them verbatim — downstream consumers
// (and the legacy parser) treat unresolved specifiers as part of the
// identity rather than normalising them, which avoids two packages that
// composer treats as distinct collapsing onto the same node.
func pkgID(name, version string) string {
	return name + "@" + version
}

// buildDepGraphs produces a single-element slice containing the root
// dep graph for a composer project. The slice shape (vs returning a bare
// *DepGraph) keeps the per-result handling in plugin.go uniform with the
// npm/yarn plugins, where workspace projects emit multiple graphs.
func buildDepGraphs(rootName, rootVersion string, parsed *parsedOutput) ([]depGraphResult, error) {
	rootGraph, err := buildSingleDepGraph(rootName, rootVersion, parsed)
	if err != nil {
		return nil, fmt.Errorf("building root dep graph: %w", err)
	}
	return []depGraphResult{{graph: rootGraph, composerJSONRelDir: ""}}, nil
}

// buildSingleDepGraph constructs the root dep graph from the parsed
// adjacency. It DFS-walks from RootDeps through Graph, deduplicating
// nodes via a visited set and breaking cycles by not recursing into an
// already-visited node.
func buildSingleDepGraph(rootName, rootVersion string, parsed *parsedOutput) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[string]bool)

	for _, id := range parsed.RootDeps {
		if err := addNode(builder, rootNodeID, id, parsed.Graph, visited); err != nil {
			return nil, err
		}
	}
	return builder.Build(), nil
}

// addNode adds id to the dep graph (if not already visited) and connects
// it to parentID. Cycles in the input adjacency are handled by the
// visited set: a node already in the set is connected but not re-walked.
func addNode(
	builder *godepgraph.Builder,
	parentID, id string,
	forward map[string]map[string]struct{},
	visited map[string]bool,
) error {
	connect := func() error {
		if err := builder.ConnectNodes(parentID, id); err != nil {
			return fmt.Errorf("connecting %s → %s: %w", parentID, id, err)
		}
		return nil
	}

	if !visited[id] {
		visited[id] = true
		name, version := splitPkgID(id)
		builder.AddNode(id, &godepgraph.PkgInfo{Name: name, Version: version})

		for _, childID := range sortedKeys(forward[id]) {
			if err := addNode(builder, id, childID, forward, visited); err != nil {
				return err
			}
		}
	}
	return connect()
}

// splitPkgID splits a full package ID ("name@version") at the last '@'.
// Composer package names use vendor/name syntax and never contain '@',
// so the last '@' is unambiguous.
//
// Examples:
//
//	"guzzlehttp/guzzle@7.8.0"   → ("guzzlehttp/guzzle", "7.8.0")
//	"php@>=7.2.5"               → ("php", ">=7.2.5")
//	"ext-json@*"                → ("ext-json", "*")
func splitPkgID(id string) (name, version string) {
	i := strings.LastIndex(id, "@")
	if i <= 0 {
		return id, ""
	}
	return id[:i], id[i+1:]
}

// sortedKeys returns the keys of m in deterministic (lexicographic)
// order. Used so the dep graph builder visits children in a stable order
// and the resulting goldens are reproducible across runs.
func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Avoid sort import bloat: insertion sort is fine for the small
	// fan-out a single composer node has (rarely >20 children).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
