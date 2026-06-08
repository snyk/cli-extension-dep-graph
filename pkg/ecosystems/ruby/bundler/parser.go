// Package bundler implements a native parser for Bundler's Gemfile.lock
// format and a SCAPlugin that turns it into a Snyk dep graph.
//
// The lockfile format is a simple indentation-driven text grammar with a
// fixed set of top-level section headers (GEM, GIT, PATH, PLATFORMS,
// DEPENDENCIES, BUNDLED WITH, RUBY VERSION, DEPENDENCIES). Each source
// block (GEM/GIT/PATH) carries a `specs:` list of resolved gems with
// their direct dependencies indented underneath. See:
// https://bundler.io/v2.5/man/gemfile.5.html and
// https://bundler.io/v2.5/man/bundle-lock.1.html
//
// This parser ports the logic of @snyk/gemfile (~150 LoC JS state
// machine) to Go. Compared to the legacy parser we:
//   - keep per-spec source metadata (GEM vs GIT vs PATH + remote/ref);
//   - drop the "extractMeta" two-mode API in favor of a single
//     structured Lockfile result.
package bundler

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// section identifies the current top-level block being read.
type section int

const (
	sectionNone section = iota
	sectionGEM
	sectionGIT
	sectionPATH
	sectionPlatforms
	sectionDependencies
	sectionBundledWith
	sectionRubyVersion
	sectionOther // for unknown headers — skipped gracefully
)

// Parse reads a Gemfile.lock from r and returns the parsed Lockfile.
// Whitespace-only files and files missing required sections still parse
// (legacy @snyk/gemfile prints a warning but returns whatever it has);
// the caller decides whether the result is usable.
func Parse(r io.Reader) (*Lockfile, error) {
	if r == nil {
		return nil, errors.New("bundler.Parse: nil reader")
	}

	lf := &Lockfile{Specs: make(map[string]*Spec)}

	sc := bufio.NewScanner(r)
	// Gemfile.lock lines are short, but bufio's default 64 KiB max-token
	// is fine — bumped to 1 MiB just in case of very large lockfiles.
	const maxLine = 1 << 20
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	var (
		cur       section = sectionNone
		curSource *SourceMeta
		// curSpec is the most recently-opened spec whose deps lines
		// (indent depth 6) we may still be reading.
		curSpec *Spec
	)

	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)

		// Blank line terminates the current spec/source/section boundary
		// only between blocks — we treat it as "leave curSpec open for
		// the next non-blank line to decide". A blank between blocks is
		// followed by a top-level header so curSource/curSpec get reset
		// there.
		if trimmed == "" {
			continue
		}

		// Top-level header lines have no indentation.
		if !startsWithSpace(raw) {
			cur = parseHeader(trimmed)
			curSpec = nil
			switch cur {
			case sectionGEM:
				curSource = &SourceMeta{Type: SourceGEM}
			case sectionGIT:
				curSource = &SourceMeta{Type: SourceGIT}
			case sectionPATH:
				curSource = &SourceMeta{Type: SourcePATH}
			default:
				curSource = nil
			}
			continue
		}

		switch cur {
		case sectionGEM, sectionGIT, sectionPATH:
			parseSourceLine(raw, trimmed, curSource, &curSpec, lf)
		case sectionPlatforms:
			lf.Platforms = append(lf.Platforms, trimmed)
		case sectionDependencies:
			lf.Dependencies = append(lf.Dependencies, parseDependencyLine(trimmed))
		case sectionBundledWith:
			// Single value line beneath BUNDLED WITH; if multiple appear, keep the first.
			if lf.BundledWith == "" {
				lf.BundledWith = trimmed
			}
		case sectionRubyVersion:
			if lf.RubyVersion == "" {
				lf.RubyVersion = strings.TrimPrefix(trimmed, "ruby ")
			}
		case sectionOther, sectionNone:
			// Unknown section: skip.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("bundler.Parse: scanning lockfile: %w", err)
	}

	return lf, nil
}

// parseHeader returns the section for a top-level header line (already trimmed).
// Unknown headers map to sectionOther; the parser skips their body.
func parseHeader(line string) section {
	switch line {
	case "GEM":
		return sectionGEM
	case "GIT":
		return sectionGIT
	case "PATH":
		return sectionPATH
	case "PLATFORMS":
		return sectionPlatforms
	case "DEPENDENCIES":
		return sectionDependencies
	case "BUNDLED WITH":
		return sectionBundledWith
	case "RUBY VERSION":
		return sectionRubyVersion
	default:
		return sectionOther
	}
}

// parseSourceLine handles a single line inside a GEM/GIT/PATH block.
// Indent depth disambiguates the role:
//
//	2 spaces ("  remote: foo")  → source metadata key/value
//	2 spaces ("  specs:")       → start of specs list (state marker)
//	4 spaces ("    name (1.0)") → spec entry (opens curSpec)
//	6 spaces ("      child")    → dependency child of the current spec
func parseSourceLine(raw, trimmed string, src *SourceMeta, curSpec **Spec, lf *Lockfile) {
	indent := leadingSpaces(raw)

	switch indent {
	case 2:
		// Source metadata line OR the `specs:` marker.
		key, value := splitKeyValue(trimmed)
		switch key {
		case "remote":
			if src != nil {
				src.Remote = value
			}
		case "revision":
			if src != nil {
				src.Revision = value
			}
		case "ref":
			if src != nil {
				src.Ref = value
			}
		case "branch":
			if src != nil {
				src.Branch = value
			}
		case "tag":
			if src != nil {
				src.Tag = value
			}
		case "glob":
			if src != nil {
				src.Glob = value
			}
		case "specs":
			// just a marker; nothing to record
		}
	case 4:
		// Spec entry: "name (version)" or "name (version-platform)".
		// Open a new spec; the previous spec is implicitly closed.
		name, version := parseSpecLine(trimmed)
		spec := &Spec{Name: name, Version: version, Source: src}
		// Last-write wins to match @snyk/gemfile.
		lf.Specs[name] = spec
		*curSpec = spec
	case 6:
		// Child dependency of the currently-open spec. Constraint info
		// (e.g. "(~> 2.3.0)") is discarded — only the gem name matters
		// because the resolved version is in lf.Specs.
		if *curSpec == nil {
			return
		}
		childName, _ := parseSpecLine(trimmed)
		if childName != "" {
			(*curSpec).Children = append((*curSpec).Children, childName)
		}
	default:
		// Unknown indent depth — skip rather than guessing.
	}
}

// parseSpecLine parses "name (version)" or "name (version-platform)" or
// "name" (bare; e.g. a child dep with no constraint). Anything in
// parentheses after the name is treated as the version; the rest is
// dropped. Returns ("", "") for empty input.
func parseSpecLine(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return s, ""
	}
	name = strings.TrimSpace(s[:i])
	rest := s[i+1:]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return name, ""
	}
	return name, strings.TrimSpace(rest[:j])
}

// parseDependencyLine handles one line under the DEPENDENCIES block.
// Strips the trailing `!` marker (used for git/path-sourced gems) and
// discards any version constraint in parens.
//
//	"rspec!"                  → {Name: "rspec",   Pinned: true}
//	"json"                    → {Name: "json",    Pinned: false}
//	"lynx (= 0.4.0)"          → {Name: "lynx",    Pinned: false}
//	"nokogiri (= 1.0.0)!"     → {Name: "nokogiri", Pinned: true}
func parseDependencyLine(s string) Dependency {
	s = strings.TrimSpace(s)
	// Drop "(...)" version constraint if present.
	if i := strings.IndexByte(s, '('); i >= 0 {
		// What follows the `)` may still hold the `!` marker.
		// Reconstruct as "<name><trailing-after-close>".
		if j := strings.IndexByte(s, ')'); j > i {
			s = strings.TrimSpace(s[:i]) + s[j+1:]
		} else {
			s = strings.TrimSpace(s[:i])
		}
	}
	s = strings.TrimSpace(s)

	pinned := strings.HasSuffix(s, "!")
	if pinned {
		s = strings.TrimSuffix(s, "!")
		s = strings.TrimSpace(s)
	}
	return Dependency{Name: s, Pinned: pinned}
}

// splitKeyValue splits "key: value" on the first ':'. Returns the key
// and value with surrounding whitespace stripped. If no ':' is found,
// returns the whole input as the key and an empty value.
func splitKeyValue(s string) (key, value string) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return strings.TrimSpace(s), ""
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
}

// leadingSpaces returns the count of leading ' ' characters in s.
// (Tabs are not used in Gemfile.lock by bundler; they would be counted
// as non-space and produce indent 0, which downstream code treats as
// "skip / unknown".)
func leadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

// startsWithSpace reports whether s begins with one or more spaces or tabs.
func startsWithSpace(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c == ' ' || c == '\t'
}
