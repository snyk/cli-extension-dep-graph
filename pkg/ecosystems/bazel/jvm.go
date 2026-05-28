package bazel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// label is an identifier for a Bazel target.
// See https://bazel.build/concepts/labels
type label string

// mavenLookup maps Bazel target labels to Snyk dep-graph PkgInfo.
// It is created from the Bazel rules_jvm_external lockfile (maven_install.json).
type mavenLookup map[label]depgraph.PkgInfo

// jvmExternalResolver implements the bazelDependencyResolver interface.
// It provides functions to find Bazel targets and build dependency graphs
// on projects that use the Bazel rules_jvm_external ruleset.
type jvmExternalResolver struct {
	dir    string
	lookup mavenLookup
}

// mavenInstallJSON encapsulates the rules_jvm_external lockfile (maven_install.json).
type mavenInstallJSON struct {
	Artifacts map[string]struct {
		Version string `json:"version"`
	} `json:"artifacts"`
}

func newJVMExternalResolver(dir string) (bazelDependencyResolver, error) {
	path := filepath.Join(dir, "maven_install.json")
	lookup, err := createMavenLookup(path)
	if err != nil {
		return nil, err
	}
	return &jvmExternalResolver{dir, lookup}, nil
}

func createMavenLookup(path string) (mavenLookup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("required file does not exist: %s", path)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lockfile mavenInstallJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", path, err)
	}
	lookup := make(mavenLookup, len(lockfile.Artifacts))
	for k, v := range lockfile.Artifacts {
		a := parseArtifactName(k)
		if a.label == "" {
			continue
		}
		lookup[a.label] = depgraph.PkgInfo{
			Name:    a.name,
			Version: v.Version,
		}
	}
	return lookup, nil
}

// mavenArtifact represents a Maven artifact with expected Bazel target label and groupId:artifactId name.
// This allows us to perform a reverse lookup of Bazel target label to Maven coordinate.
type mavenArtifact struct {
	label label
	name  string
}

// parseArtifactName converts artifact names found in the rules_jvm_external lockfile to
// Bazel target labels and groupId:artifactId names.
// rules_jvm_external normalizes names using the format group:artifact[:packaging[:classifier]].
// See: https://github.com/bazel-contrib/rules_jvm_external/blob/master/private/rules/artifact.bzl
func parseArtifactName(name string) mavenArtifact {
	if name == "" {
		return mavenArtifact{}
	}

	parts := strings.Split(name, ":")
	var l string
	var n string

	switch len(parts) {
	case 1:
		l = parts[0]
		n = parts[0]
	case 2:
		// groupId:artifactId
		l = fmt.Sprintf("%s_%s", parts[0], parts[1])
		n = name
	case 3:
		// groupId:artifactId:packaging
		// rules_jvm_external drops the packaging type (e.g., 'aar', 'pom') from the label
		l = fmt.Sprintf("%s_%s", parts[0], parts[1])
		n = fmt.Sprintf("%s:%s", parts[0], parts[1])
	case 4:
		// groupId:artifactId:packaging:classifier
		// packaging is dropped from the label; classifier distinguishes the Bazel target label.
		l = fmt.Sprintf("%s_%s_%s", parts[0], parts[1], parts[3])
		n = fmt.Sprintf("%s:%s", parts[0], parts[1])
	default:
		return mavenArtifact{}
	}

	// apply rules_jvm_external character replacements
	replacer := strings.NewReplacer(".", "_", "-", "_", "$", "_")
	return mavenArtifact{
		label: label(replacer.Replace(l)),
		name:  n,
	}
}

func (r *jvmExternalResolver) packageManagerName() string {
	// For vulnerability matching we use 'maven' as the dep-graph package manager name.
	return "maven"
}

// processedFiles returns empty because rules_jvm_external projects have no
// pom.xml or build.gradle files that the legacy CLI would otherwise re-scan.
func (r *jvmExternalResolver) processedFiles() []string {
	return []string{}
}

func (r *jvmExternalResolver) findTargets(ctx context.Context, options *ecosystems.SCAPluginOptions) ([]string, error) {
	query := "kind('java_binary', //...)"
	if options != nil && options.Bazel.TargetQuery != "" {
		query = options.Bazel.TargetQuery
	}

	output, err := bazelQuery(ctx, r.dir, query)
	if err != nil {
		return nil, fmt.Errorf(errQueryBazelTargetsFmt, err)
	}

	var targets []string
	for _, result := range output.Results {
		if result.Target == nil || result.Target.Rule == nil {
			continue
		}
		if n := result.Target.Rule.Name; n != "" {
			targets = append(targets, n)
		}
	}

	return targets, nil
}

func (r *jvmExternalResolver) buildDepGraph(ctx context.Context, targetName string) (*depgraph.DepGraph, error) {
	labelDeps, err := r.queryDeps(ctx, targetName)
	if err != nil {
		return nil, fmt.Errorf("failed to query dependencies: %w", err)
	}

	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: r.packageManagerName()},
		&depgraph.PkgInfo{Name: targetName},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create builder: %w", err)
	}

	labelInGraph := make(map[string]bool)
	labelInGraph[targetName] = true

	labelQueue := []string{targetName}

	for len(labelQueue) > 0 {
		label := labelQueue[0]
		labelQueue = labelQueue[1:]

		for _, childLabel := range labelDeps[label] {
			if childLabel == "" {
				continue
			}

			if !labelInGraph[childLabel] {
				labelInGraph[childLabel] = true
				childPkgInfo := r.labelToPkgInfo(childLabel)
				builder.AddNode(childLabel, childPkgInfo)
				labelQueue = append(labelQueue, childLabel)
			}

			parentNodeID := getParentNodeID(builder, targetName, label)
			if err := builder.ConnectNodes(parentNodeID, childLabel); err != nil {
				return nil, fmt.Errorf("failed to connect nodes %s and %s: %w", label, childLabel, err)
			}
		}
	}

	return builder.Build(), nil
}

func getParentNodeID(builder *depgraph.Builder, rootLabel, label string) string {
	if label == rootLabel {
		return builder.GetRootNode().NodeID
	}
	return label
}

// queryDeps performs a bazel deps query and constructs a lookup of label dependencies.
func (r *jvmExternalResolver) queryDeps(ctx context.Context, targetName string) (map[string][]string, error) {
	query := "deps(" + targetName + ")"
	output, err := bazelQuery(ctx, r.dir, query)
	if err != nil {
		return nil, fmt.Errorf("bazel cquery failed %s: %w", query, err)
	}

	labelDeps := make(map[string][]string)
	for _, result := range output.Results {
		if result.Target == nil || result.Target.Type != "RULE" || result.Target.Rule == nil {
			continue
		}

		var deps []string
		for _, attr := range result.Target.Rule.Attribute {
			// only rules with these attributes are JVM dependencies
			if attr.Name == "deps" || attr.Name == "runtime_deps" || attr.Name == "exports" {
				deps = append(deps, attr.StringListValue...)
			}
		}
		labelDeps[result.Target.Rule.Name] = deps
	}

	return labelDeps, nil
}

// labelToPkgInfo converts a Bazel Target label to a Snyk package info object.
// See https://bazel.build/concepts/labels for more information on Bazel Target labels.
func (r *jvmExternalResolver) labelToPkgInfo(l string) *depgraph.PkgInfo {
	pkgInfo := &depgraph.PkgInfo{
		Name: l, // use the Bazel label name by default
	}

	// lookup maven coordinate
	if l != "" && l[0] == '@' {
		i := strings.LastIndexByte(l, ':')
		if i != -1 && i < len(l)-1 {
			k := label(l[i+1:])
			if v, ok := r.lookup[k]; ok {
				pkgInfo.Name = v.Name
				pkgInfo.Version = v.Version
			}
		}
	}

	return pkgInfo
}
