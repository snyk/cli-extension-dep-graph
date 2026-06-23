package yarn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// virtualRe matches Berry's @virtual:<hash># infix. Removing the match
// collapses peer-virtualised locators onto their underlying real package id:
//
//	"debug@virtual:abc123#npm:4.3.1"  →  "debug@npm:4.3.1"
//
// Non-greedy [^#]+ rather than .* so we don't over-consume if a locator ever
// carries multiple #-separated segments.
var virtualRe = regexp.MustCompile(`@virtual:[^#]+#`)

// berryEntry mirrors the shape of a single NDJSON line emitted by
// `yarn info --all --recursive --json`. Many other fields exist
// (Dependents, Instances, "Exported Binaries"…) — we ignore them.
//
// Version / Dependencies are intentionally Pascal-cased because Berry emits
// the wire format with those exact keys; the camelCase tagliatelle warning
// doesn't apply to keys we don't control.
//
//nolint:tagliatelle // Berry's wire format uses PascalCase keys we don't control
type berryEntry struct {
	Value    string `json:"value"`
	Children struct {
		Version      string `json:"Version"`
		Dependencies []struct {
			Descriptor string `json:"descriptor"`
			Locator    string `json:"locator"`
		} `json:"Dependencies"`
	} `json:"children"`
}

// parseYarnInfoOutput parses Berry `yarn info --all --recursive --json` output.
//
// Berry emits NDJSON: one JSON object per line, each describing a resolved
// package and its direct dependencies. The root workspace appears as a value
// ending in "@workspace:."; workspace members end in "@workspace:<path>".
//
// Locators carry protocol prefixes (npm:, workspace:, file:, patch:, …) and
// peer-virtual entries embed a `@virtual:<hash>#` infix. We de-virtualise
// locators on both sides of each edge so peer-virtualised packages collapse
// onto a single graph node; protocol prefixes are kept on graph keys and
// stripped only at PkgInfo extraction time by splitPkgID.
//
// Yarn info does not distinguish dev from prod dependencies. Everything from
// the root workspace's Dependencies array lands in ProdDeps; DevDeps stays
// empty. Dep graph consumers don't currently care about the split.
func parseYarnInfoOutput(
	ctx context.Context,
	log logger.Logger,
	r io.Reader,
	_ *packageJSON,
) (*parsedOutput, error) {
	out := &parsedOutput{
		Graph:      make(forwardGraph),
		Workspaces: make(map[string]workspaceInfo),
	}
	seenProd := make(map[string]struct{})

	scanner := bufio.NewScanner(r)
	// yarn info lines can be very long for projects with many transitive deps
	// (the entry for a top-level package can list hundreds of dependencies).
	// Default 64KB is too small; allow up to 4MB per line.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 4*1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++

		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		var entry berryEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			log.Debug(ctx, "Skipping unparseable yarn info line",
				logger.Attr("line", lineNum), logger.Err(err))
			continue
		}

		locator := devirtualise(entry.Value)

		deps := make(map[string]struct{}, len(entry.Children.Dependencies))
		for _, d := range entry.Children.Dependencies {
			deps[devirtualise(d.Locator)] = struct{}{}
		}

		kind, wsDir := classifyLocator(locator)
		switch kind {
		case locatorRoot:
			// Root workspace — extract its deps as the seed set for the root graph.
			for d := range deps {
				if _, ok := seenProd[d]; ok {
					continue
				}
				seenProd[d] = struct{}{}
				out.ProdDeps = append(out.ProdDeps, d)
			}

		case locatorWorkspace:
			// Workspace member — both a node in the graph AND its own root.
			out.Graph[locator] = deps
			name, _ := splitPkgID(locator)
			version := entry.Children.Version
			if version == "" {
				version = defaultVersion
			}
			out.Workspaces[locator] = workspaceInfo{
				Dir:     wsDir,
				Name:    name,
				Version: version,
			}

		case locatorPackage:
			out.Graph[locator] = deps
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning yarn info output: %w", err)
	}

	return out, nil
}

// locatorKind classifies a Berry locator by its version protocol.
type locatorKind int

const (
	locatorPackage   locatorKind = iota // npm:, file:, patch:, …
	locatorRoot                         // workspace:.
	locatorWorkspace                    // workspace:<non-dot path>
)

// classifyLocator returns the kind plus, for workspace locators, the workspace
// directory relative to the lockfile.
//
//	"name@workspace:."           → root,      dir=""
//	"name@workspace:packages/x"  → workspace, dir="packages/x"
//	"name@npm:1.2.3"             → package,   dir=""
//	"name@file:./local"          → package,   dir=""
func classifyLocator(locator string) (kind locatorKind, wsDir string) {
	i := strings.LastIndex(locator, "@")
	if i <= 0 {
		return locatorPackage, ""
	}
	version := locator[i+1:]
	if !strings.HasPrefix(version, "workspace:") {
		return locatorPackage, ""
	}
	path := strings.TrimPrefix(version, "workspace:")
	if path == "." {
		return locatorRoot, ""
	}
	return locatorWorkspace, path
}

// devirtualise strips Berry's @virtual:<hash># infix from a locator. Idempotent
// on locators that don't carry a virtual prefix.
func devirtualise(locator string) string {
	return virtualRe.ReplaceAllString(locator, "@")
}
