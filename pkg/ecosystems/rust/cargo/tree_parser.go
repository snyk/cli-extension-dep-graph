package cargo

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// treeLineRe matches a line produced by
// `cargo tree --prefix=depth --no-dedupe --format='{p}'`.
//
// Group 1: depth (one or more digits at the start of the line)
// Group 2: package name (non-space token, e.g. "serde", "proc-macro2")
// Group 3: version (non-space token; the "v" prefix from cargo is stripped)
// Group 4: trailing annotations (source path/URL, "(proc-macro)", cycle "(*)")
//
// Examples:
//
//	"0my-app v0.1.0 (/path/to/my-app)"     → 0, "my-app",       "0.1.0",  " (/path/to/my-app)"
//	"1serde v1.0.193"                      → 1, "serde",        "1.0.193", ""
//	"2serde_derive v1.0.193 (proc-macro)"  → 2, "serde_derive", "1.0.193", " (proc-macro)"
//	"3foo v1.0.0 (*)"                      → 3, "foo",          "1.0.0",   " (*)"
//
// Trailing annotations are captured but not yet consumed — git/path source
// disambiguation in node IDs is deferred (see types.go). The cycle marker (*)
// is harmless: cargo only emits children of a (*) node above it in the output,
// so the parser's depth stack naturally treats it as a leaf.
var treeLineRe = regexp.MustCompile(`^(\d+)(\S+)\sv(\S+)(.*)$`)

// parseTree scans cargo-tree output from r and returns the parsed forward
// graph plus the root package ID. Each line declares a node at a particular
// depth; the parser maintains a stack of (depth, id) tuples and emits an edge
// from the nearest shallower node to the current one.
//
// Lines that do not match treeLineRe are logged at Debug and skipped — this
// covers blank lines and any future cargo tree decorations we have not
// modeled yet (e.g. `[build-dependencies]` section headers, if cargo emits
// them in this format).
func parseTree(ctx context.Context, log logger.Logger, r io.Reader) (*treeOutput, error) {
	if log == nil {
		log = logger.Nop()
	}

	scanner := bufio.NewScanner(r)
	out := &treeOutput{Graph: make(forwardGraph)}

	type frame struct {
		depth int
		id    string
	}

	var stack []frame

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		m := treeLineRe.FindStringSubmatch(line)
		if m == nil {
			log.Debug(ctx, "Skipping unrecognized cargo tree output line", logger.Attr("line", line))
			continue
		}

		depth, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("parsing depth %q: %w", m[1], err)
		}

		id := m[2] + "@" + m[3]

		if _, exists := out.Graph[id]; !exists {
			out.Graph[id] = make(map[string]struct{})
		}

		// Pop frames at or beyond current depth — they are no longer ancestors.
		for len(stack) > 0 && stack[len(stack)-1].depth >= depth {
			stack = stack[:len(stack)-1]
		}

		switch {
		case depth == 0:
			// First depth-0 line is the root. Subsequent depth-0 lines (workspace
			// siblings printed sequentially) are recorded as nodes in the graph
			// but do not overwrite the root — workspace handling lands in a later
			// step and runs cargo tree per member.
			if out.RootID == "" {
				out.RootID = id
			}
		case len(stack) > 0:
			parent := stack[len(stack)-1].id
			out.Graph[parent][id] = struct{}{}
		default:
			// Non-zero depth with no parent in scope: malformed output. Surface
			// rather than silently dropping the edge.
			return nil, fmt.Errorf("depth %d node %q has no parent in scope", depth, id)
		}

		stack = append(stack, frame{depth: depth, id: id})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning cargo tree output: %w", err)
	}

	if out.RootID == "" {
		return nil, fmt.Errorf("no root package found in cargo tree output")
	}

	return out, nil
}
