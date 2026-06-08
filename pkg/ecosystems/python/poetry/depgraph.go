package poetry

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// ignoredDeps matches the legacy snyk-poetry-lockfile-parser ignore
// list. These packages are bundled by poetry's virtualenv setup itself
// and never appear in the lockfile, so the tree shouldn't reference
// them either.
var ignoredDeps = map[string]struct{}{
	"setuptools": {},
	"distribute": {},
	"pip":        {},
	"wheel":      {},
}

// Regexes for the two line shapes `poetry show --tree` produces.
//
// Top-level (no leading indent at all):
//
//	flask 2.3.2 A simple framework for building complex web applications.
//	six 1.17.0 Python 2 and 3 compatibility utilities
//
// Transitive (preceded by tree-drawing characters and ASCII indents):
//
//	├── blinker >=1.6.2
//	│   └── colorama *
//	└── werkzeug >=2.3.3
//
// We match the package token + the rest of the line (version or
// constraint), tolerating poetry's optional trailing description.
var (
	// topLevelLineRe matches `<name> <version> [description...]`
	// where `<name>` is an unindented package id.
	topLevelLineRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(\S+)(?:\s+.*)?$`)

	// childLineRe matches `[│ ]*[├└]── <name> <constraint>[ rest]`.
	// The constraint may be `*` (any), a PEP 440 spec like `>=1.2`,
	// or `(!=...)`. We grab `<name>` and the token immediately after.
	childLineRe = regexp.MustCompile(`[├└]──\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+(\S+)(?:\s+.*)?$`)
)

// parseTreeOutput reads `poetry show --tree --no-ansi` output and
// returns the parsed forest of top-level packages with their nested
// children. Lines that don't match either expected pattern are
// silently dropped — poetry occasionally prints blank lines between
// top-level entries and we want to ignore them rather than abort.
func parseTreeOutput(r io.Reader) ([]*treeNode, error) {
	scanner := bufio.NewScanner(r)
	// Poetry trees can be wide; bump the line buffer well above
	// bufio's 64KB default to avoid spurious truncation on big graphs.
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	// stack tracks the most recent parent at each depth so child lines
	// can attach to the correct ancestor without an O(n^2) lookup.
	var roots []*treeNode
	var stack []*treeNode

	for scanner.Scan() {
		raw := scanner.Text()
		// Drop CR for CRLF-terminated streams (Windows poetry builds).
		raw = strings.TrimRight(raw, "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}

		// Top-level lines have no tree-drawing characters and no leading
		// indent. We test the indent-free shape first so we don't waste
		// the more expensive child regex on top-level entries.
		if !strings.ContainsAny(raw, "├└│") && !strings.HasPrefix(raw, " ") {
			m := topLevelLineRe.FindStringSubmatch(raw)
			if m == nil {
				// Not a recognized format (header line, summary, etc.) — skip.
				continue
			}
			node := &treeNode{Name: m[1], Version: m[2], Depth: 0}
			roots = append(roots, node)
			stack = stack[:0]
			stack = append(stack, node)
			continue
		}

		// Child line. Depth is determined by the count of indent units
		// preceding the tree branch character. Each level in poetry's
		// tree is exactly 4 columns: `│   ` (cont) or `    ` (last).
		depth := childDepth(raw)
		m := childLineRe.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		node := &treeNode{Name: m[1], Version: m[2], Depth: depth}

		// Pop the stack to the parent. Top-level node lives at index 0
		// (depth 0); depth==1 attaches to stack[0]; depth==2 attaches
		// to stack[1]; in general parent index is depth-1.
		if depth-1 < 0 || depth-1 >= len(stack) {
			// Malformed indent — drop the line rather than crash the
			// whole resolve. This protects us if poetry ever introduces
			// a new node shape we haven't seen.
			continue
		}
		parent := stack[depth-1]
		parent.Children = append(parent.Children, node)

		// Truncate stack at depth and push self so the next child knows
		// who its parent is.
		stack = stack[:depth]
		stack = append(stack, node)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading poetry show output: %w", err)
	}
	return roots, nil
}

// childDepth counts the number of 4-column indent prefixes ahead of
// the `├` or `└` branch character. Poetry uses a fixed indent width.
//
// Examples:
//
//	"├── foo"           → 1
//	"│   └── bar"       → 2
//	"    │   └── baz"   → 3
func childDepth(line string) int {
	// We treat each 4-character run beginning with `│` or space as one
	// level. The branch char (`├`/`└`) marks the start of this node's
	// own segment, which itself counts as the deepest level — hence +1.
	depth := 0
	i := 0
	for i+4 <= len(line) {
		seg := line[i : i+4]
		// '│' is multi-byte in UTF-8 (3 bytes), so a literal prefix
		// like "│   " is actually 6 bytes long. Branch into a slow
		// path that handles either form.
		if strings.HasPrefix(line[i:], "│") {
			// Slow path: advance past the multi-byte char and the
			// following 3 padding spaces.
			i += len("│")
			// Tolerate poetry's variable padding (some builds emit a
			// hard space, others use NBSP-equivalents — bound to ≤3).
			for j := 0; j < 3 && i < len(line) && line[i] == ' '; j++ {
				i++
			}
			depth++
			continue
		}
		if seg == "    " {
			i += 4
			depth++
			continue
		}
		break
	}
	// The branch character itself (`├`/`└`) opens the current node's
	// segment, which is the next level down.
	return depth + 1
}

// buildDepGraphFromTree converts the parsed tree into a Snyk DepGraph
// rooted at root. Transitive constraint strings (the tokens after a
// child's name) are resolved to concrete versions via topLevelByName,
// so the graph nodes carry the same versions the lockfile pinned.
//
// Packages in ignoredDeps (setuptools / pip / wheel / distribute) are
// dropped wherever they appear, matching legacy behaviour. Cycles are
// broken by tracking the visited path per DFS branch — a re-entry
// emits a pruned leaf node tagged `pruned=true` (same convention as
// the python/pip plugin).
func buildDepGraphFromTree(
	ctx context.Context,
	log logger.Logger,
	root rootPkg,
	roots []*treeNode,
) (*depgraph.DepGraph, error) {
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: PkgManagerName},
		&depgraph.PkgInfo{Name: root.Name, Version: root.Version},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	// Index top-level entries by normalised name so transitive
	// constraints can be resolved to concrete versions. Poetry prints
	// every installed package as a top-level entry in addition to
	// nesting it under its parents, so this index is total.
	topLevelByName := make(map[string]*treeNode, len(roots))
	for _, n := range roots {
		topLevelByName[normalizeName(n.Name)] = n
	}

	rootID := builder.GetRootNode().NodeID
	processed := make(map[string]bool) // dedup edges across multi-paths

	for _, top := range roots {
		if _, skip := ignoredDeps[normalizeName(top.Name)]; skip {
			continue
		}
		if err := addChild(builder, log, ctx, rootID, top, topLevelByName, nil, processed); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addChild adds node under parentID, resolving its concrete version
// from topLevelByName when the printed token looked like a constraint.
// visited carries the set of node IDs already on the current DFS
// branch so re-entries can be emitted as pruned leaves; processed
// stops the recursion once a node's subtree has already been built.
func addChild(
	builder *depgraph.Builder,
	log logger.Logger,
	ctx context.Context,
	parentID string,
	node *treeNode,
	topLevelByName map[string]*treeNode,
	visited map[string]bool,
	processed map[string]bool,
) error {
	if _, skip := ignoredDeps[normalizeName(node.Name)]; skip {
		return nil
	}

	resolved := resolveVersion(node, topLevelByName)
	if resolved == "" {
		// Poetry printed a child whose package isn't listed at the
		// top level — most often happens when the lockfile is out of
		// sync with the manifest. Skip rather than abort so the rest
		// of the graph is still useful.
		log.Debug(ctx, "skipping unresolvable dependency",
			logger.Attr("name", node.Name),
			logger.Attr("constraint", node.Version),
		)
		return nil
	}

	nodeID := nodeIDOf(node.Name, resolved)

	// Cycle detection. We allocate the visited set lazily so the common
	// (acyclic) path doesn't pay for it.
	localVisited := visited
	if localVisited == nil {
		localVisited = make(map[string]bool)
	}
	if localVisited[nodeID] {
		prunedID := nodeID + ":pruned"
		builder.AddNode(prunedID, &depgraph.PkgInfo{
			Name:    normalizeName(node.Name),
			Version: resolved,
		}, depgraph.WithNodeInfo(&depgraph.NodeInfo{
			Labels: map[string]string{"pruned": "true"},
		}))
		if err := builder.ConnectNodes(parentID, prunedID); err != nil {
			return fmt.Errorf("connecting pruned %s -> %s: %w", parentID, prunedID, err)
		}
		return nil
	}

	builder.AddNode(nodeID, &depgraph.PkgInfo{
		Name:    normalizeName(node.Name),
		Version: resolved,
	})
	if err := builder.ConnectNodes(parentID, nodeID); err != nil {
		return fmt.Errorf("connecting %s -> %s: %w", parentID, nodeID, err)
	}

	localVisited[nodeID] = true

	// Only descend once per node — dedupes edges for diamond deps.
	if !processed[nodeID] {
		processed[nodeID] = true
		// Recurse into the canonical entry for this package so we walk
		// every transitive dep, not just the ones the constraint line
		// happens to list (poetry's tree may collapse identical sub-trees).
		source := topLevelByName[normalizeName(node.Name)]
		if source == nil {
			source = node
		}
		for _, child := range source.Children {
			if err := addChild(builder, log, ctx, nodeID, child, topLevelByName, localVisited, processed); err != nil {
				return err
			}
		}
	}

	delete(localVisited, nodeID)
	return nil
}

// resolveVersion turns the printed `<version-or-constraint>` token into
// a concrete version string by looking the package up in the top-level
// index. The top-level entry always carries the resolved version (the
// lockfile pin), so this is total whenever the package is known.
//
// When the printed token already looks like a concrete version (i.e.
// matches the top-level entry) we return it unchanged. Anything else
// is treated as a constraint and resolved via the index.
func resolveVersion(node *treeNode, topLevelByName map[string]*treeNode) string {
	top, ok := topLevelByName[normalizeName(node.Name)]
	if !ok {
		// Unknown package: fall back to whatever poetry printed so the
		// graph still contains a useful version-shaped string. The
		// `addChild` caller will log a debug for this case.
		if isConstraint(node.Version) {
			return ""
		}
		return node.Version
	}
	return top.Version
}

// isConstraint heuristically reports whether s looks like a version
// constraint (e.g. `>=1.2`, `*`, `(<3,>=1.2)`) rather than a concrete
// version. We use this only to decide whether to drop the value when
// we can't resolve it — we don't try to parse PEP 440 semantics here.
func isConstraint(s string) bool {
	if s == "*" || s == "" {
		return true
	}
	for _, c := range s {
		switch c {
		case '>', '<', '=', '!', '~', '^', '(', '[', '|', ',':
			return true
		}
	}
	return false
}

// normalizeName follows PEP 503: lowercase, treat `_` and `-` as equivalent.
func normalizeName(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

// nodeIDOf is the canonical node ID format used in graphs produced by
// this plugin (matches python/pip/python/pipenv conventions).
func nodeIDOf(name, version string) string {
	return normalizeName(name) + "@" + version
}
