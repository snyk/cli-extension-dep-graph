package cocoapods

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// specRe matches a pod specification or dependency string. Group 1 is
// the name, group 2 (optional) is the parenthesised version or version
// requirement. Mirrors the regex in @snyk/snyk-cocoapods-plugin/utils.ts
// so identity (name extracted from specs) matches the legacy plugin.
//
// Examples it must accept:
//
//	"Adjust (4.17.1)"
//	"Adjust/Core (4.17.1)"
//	"ReactiveObjC (~> 2.0)"
//	"AFNetworking/NSURLConnection (= 2.5.4)"
//	"Pulley (from `https://github.com/l2succes/Pulley.git`, branch `master`)"
//	"Expecta"                                — no version
//	"Artsy+UIColors (3.1.0)"                — '+' is part of the name
var specRe = regexp.MustCompile(`^((?:\s?[^\s(])+)(?: \((.+)\))?$`)

// fromRequirementRe matches the "from `...`"  form a Podfile dependency
// uses to point at an external source. When the version-like field is
// actually a from-clause the dependency carries no resolved version, so
// the parser drops it (matches legacy behaviour in utils.ts).
var fromRequirementRe = regexp.MustCompile("from `(.*)(`|')")

// PkgInfo is the (name, version) pair extracted from a specification or
// dependency string. version may be empty when the string had no
// parenthesised tail or when the tail was a "from `...`" clause.
type PkgInfo struct {
	Name    string
	Version string
}

// ParseSpecification parses a string like "AFNetworking/NSURLConnection (2.5.4)"
// from the PODS section. The version inside parens is the resolved
// version of the pod; it is always present for PODS entries (CocoaPods
// guarantees resolved versions in the lockfile).
func ParseSpecification(s string) (PkgInfo, error) {
	m := specRe.FindStringSubmatch(s)
	if m == nil {
		return PkgInfo{}, fmt.Errorf("invalid pod specification %q", s)
	}
	return PkgInfo{Name: m[1], Version: m[2]}, nil
}

// ParseDependency parses a string from the DEPENDENCIES section or from
// a nested dep list under a PODS entry. The version field of the result
// holds the *requirement* (e.g. "~> 2.0", "= 4.17.1") rather than a
// resolved version, and is empty when the tail is missing entirely or
// when it is a "from `...`" clause pointing at an external source.
func ParseDependency(s string) (PkgInfo, error) {
	m := specRe.FindStringSubmatch(s)
	if m == nil {
		return PkgInfo{}, fmt.Errorf("invalid pod dependency %q", s)
	}
	name, ver := m[1], m[2]
	if ver == "" || fromRequirementRe.MatchString(ver) {
		return PkgInfo{Name: name}, nil
	}
	return PkgInfo{Name: name, Version: ver}, nil
}

// RootSpecName returns the leading path segment of a pod name. Subspecs
// are addressed as "Root/Sub" in Podfile.lock — CocoaPods guarantees
// each root spec resolves to exactly one version, so the root name is a
// stable node identifier across all of its subspecs.
//
//	"AFNetworking/NSURLConnection" → "AFNetworking"
//	"AFNetworking"                  → "AFNetworking"
func RootSpecName(name string) string {
	if i := strings.Index(name, "/"); i > 0 {
		return name[:i]
	}
	return name
}

// ParseLockfile reads YAML from r and produces a Lockfile. It uses a
// two-step decode because PODS entries are heterogeneous (either a bare
// string or a single-key map) and a single Go struct cannot express
// that without an interface field; decoding via yaml.Node lets us
// inspect the shape per-element. Identical pattern to the TS parser's
// `if (typeof elem === 'string') { ... } else { ... }` branching.
func ParseLockfile(r io.Reader) (*Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading Podfile.lock: %w", err)
	}

	// Decode the PODS section as yaml.Node so we can branch on element
	// kind, then decode everything else into the typed Lockfile.
	var raw struct {
		Pods             yaml.Node                  `yaml:"PODS"`
		Dependencies     []string                   `yaml:"DEPENDENCIES"`
		SpecRepos        map[string][]string        `yaml:"SPEC REPOS,omitempty"`
		ExternalSources  map[string]ExternalSource  `yaml:"EXTERNAL SOURCES,omitempty"`
		CheckoutOptions  map[string]CheckoutOptions `yaml:"CHECKOUT OPTIONS,omitempty"`
		SpecChecksums    map[string]string          `yaml:"SPEC CHECKSUMS"`
		PodfileChecksum  string                     `yaml:"PODFILE CHECKSUM,omitempty"`
		CocoapodsVersion string                     `yaml:"COCOAPODS,omitempty"`
	}

	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing Podfile.lock YAML: %w", err)
	}

	pods, err := decodePods(&raw.Pods)
	if err != nil {
		return nil, err
	}

	return &Lockfile{
		Pods:             pods,
		Dependencies:     raw.Dependencies,
		SpecRepos:        raw.SpecRepos,
		ExternalSources:  raw.ExternalSources,
		CheckoutOptions:  raw.CheckoutOptions,
		SpecChecksums:    raw.SpecChecksums,
		PodfileChecksum:  raw.PodfileChecksum,
		CocoapodsVersion: raw.CocoapodsVersion,
	}, nil
}

// decodePods converts the heterogeneous PODS sequence into typed
// PodEntry values. Each element is either a scalar (no deps) or a
// single-key map whose value is the list of dependency strings.
func decodePods(n *yaml.Node) ([]PodEntry, error) {
	if n == nil || n.Kind == 0 {
		return nil, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("PODS: expected sequence, got kind %d", n.Kind)
	}

	out := make([]PodEntry, 0, len(n.Content))
	for i, elem := range n.Content {
		switch elem.Kind {
		case yaml.ScalarNode:
			out = append(out, PodEntry{Spec: elem.Value})

		case yaml.MappingNode:
			if len(elem.Content) != 2 {
				return nil, fmt.Errorf("PODS[%d]: expected single-key map, got %d entries", i, len(elem.Content)/2)
			}
			keyNode, valNode := elem.Content[0], elem.Content[1]
			var deps []string
			if err := valNode.Decode(&deps); err != nil {
				return nil, fmt.Errorf("PODS[%d] (%s): decoding dependency list: %w", i, keyNode.Value, err)
			}
			out = append(out, PodEntry{Spec: keyNode.Value, Deps: deps})

		default:
			return nil, fmt.Errorf("PODS[%d]: unsupported YAML kind %d", i, elem.Kind)
		}
	}

	return out, nil
}

// ReadLockfile reads and parses a Podfile.lock from disk.
func ReadLockfile(path string) (*Lockfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	return ParseLockfile(f)
}
