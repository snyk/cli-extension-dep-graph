package bazel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gazellelabel "github.com/bazelbuild/bazel-gazelle/label"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

const (
	goModFilename = "go.mod"
	goSumFilename = "go.sum"
)

// goLookup maps Bazel repository names (e.g. "com_github_spf13_cobra") to
// Snyk dep-graph PkgInfo for the corresponding Go module. rules_go / gazelle /
// the bzlmod go_deps extension all derive repo names from module import paths
// via label.ImportPathToBazelRepoName, and source versions from go.mod.
type goLookup map[string]depgraph.PkgInfo

// goResolver implements the bazelDependencyResolver interface for projects
// using rules_go. Bazel target labels are mapped to Go module coordinates via
// a lookup built from the project's go.mod.
type goResolver struct {
	dir    string
	lookup goLookup
}

func newGoResolver(dir string) (bazelDependencyResolver, error) {
	lookup, err := createGoLookup(filepath.Join(dir, goModFilename))
	if err != nil {
		return nil, err
	}
	return &goResolver{dir: dir, lookup: lookup}, nil
}

// createGoLookup parses go.mod and builds the repo-name → PkgInfo lookup.
//
// Replace directives that target another versioned module are honored: the
// looked-up PkgInfo points at the replacement's module path and version, while
// the lookup key remains the original require path (which is what gazelle /
// go_deps use to name the Bazel repository).
//
// Path-only replaces (e.g. "replace foo => ../local/foo") have no version and
// can't be represented as a vuln-scannable coordinate; we keep the original
// require entry in those cases.
func createGoLookup(path string) (goLookup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("required file does not exist: %s", path)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	parsed, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", path, err)
	}

	type replacement struct {
		modulePath string
		version    string
	}
	replaces := make(map[string]replacement, len(parsed.Replace))
	for _, r := range parsed.Replace {
		if r.New.Version == "" {
			continue
		}
		replaces[r.Old.Path] = replacement{modulePath: r.New.Path, version: r.New.Version}
	}

	lookup := make(goLookup, len(parsed.Require))
	for _, req := range parsed.Require {
		modPath := req.Mod.Path
		modVersion := req.Mod.Version
		if r, ok := replaces[modPath]; ok {
			modPath = r.modulePath
			modVersion = r.version
		}

		repoName := gazellelabel.ImportPathToBazelRepoName(req.Mod.Path)
		if repoName == "" {
			continue
		}
		lookup[repoName] = depgraph.PkgInfo{
			Name:    modPath,
			Version: normalizeVersion(modVersion),
		}
	}

	return lookup, nil
}

// normalizeVersion converts a go.mod version string into the form Snyk's
// gomodules dep-graph uses: leading 'v' stripped from semver tags, and
// pseudo-versions reduced to "#<short-sha>" (the 12-char revision).
func normalizeVersion(v string) string {
	if v == "" {
		return ""
	}
	if module.IsPseudoVersion(v) {
		if rev, err := module.PseudoVersionRev(v); err == nil && rev != "" {
			return "#" + rev
		}
	}
	return strings.TrimPrefix(v, "v")
}

func (r *goResolver) packageManagerName() string {
	return "gomodules"
}

// processedFiles reports go.mod and go.sum as consumed so that the legacy CLI does not
// re-scan it after the Bazel resolver has already produced a dep-graph from it.
func (r *goResolver) processedFiles() []string {
	return []string{
		filepath.Join(r.dir, goModFilename),
		filepath.Join(r.dir, goSumFilename),
	}
}

func (r *goResolver) findTargets(ctx context.Context, options *ecosystems.SCAPluginOptions) ([]string, error) {
	query := "kind('go_binary', //...)"
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

func (r *goResolver) buildDepGraph(ctx context.Context, targetName string) (*depgraph.DepGraph, error) {
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

	labelInGraph := map[string]bool{targetName: true}
	labelQueue := []string{targetName}

	for len(labelQueue) > 0 {
		l := labelQueue[0]
		labelQueue = labelQueue[1:]

		for _, childLabel := range labelDeps[l] {
			if childLabel == "" {
				continue
			}

			if !labelInGraph[childLabel] {
				labelInGraph[childLabel] = true
				builder.AddNode(childLabel, r.labelToPkgInfo(childLabel))
				labelQueue = append(labelQueue, childLabel)
			}

			parentNodeID := getParentNodeID(builder, targetName, l)
			if err := builder.ConnectNodes(parentNodeID, childLabel); err != nil {
				return nil, fmt.Errorf("failed to connect nodes %s and %s: %w", l, childLabel, err)
			}
		}
	}

	return builder.Build(), nil
}

func (r *goResolver) queryDeps(ctx context.Context, targetName string) (map[string][]string, error) {
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
			// rules_go propagates dependencies via 'deps' (regular library
			// edges) and 'embed' (same-package compilation units).
			if attr.Name == "deps" || attr.Name == "embed" {
				deps = append(deps, attr.StringListValue...)
			}
		}
		labelDeps[result.Target.Rule.Name] = deps
	}

	return labelDeps, nil
}

// labelToPkgInfo converts a Bazel target label to a Snyk PkgInfo.
//
// External Go module targets look like "@<repo>//<pkg-path>:<target>". The
// full Go import path is "<module>/<pkg-path>" (or "<module>" when the target
// references the module root). Vulnerability data in Snyk's database is keyed
// by Go import path (not module path), so the subpackage segment matters.
//
// bzlmod canonical labels embed the apparent name as the trailing '~'/'+'
// segment (e.g. "@@rules_go~~go_deps~com_github_spf13_cobra//cobra:cobra");
// we keep only that segment for the lookup.
//
// First-party labels (no '@' prefix) and labels referencing unknown external
// repos retain the raw Bazel label as their name, with no version. This keeps
// intermediate Bazel targets navigable in the dep-graph — useful for tracing
// which target pulls in a vulnerable dependency.
func (r *goResolver) labelToPkgInfo(l string) *depgraph.PkgInfo {
	pkgInfo := &depgraph.PkgInfo{Name: l}

	if l == "" || l[0] != '@' {
		return pkgInfo
	}

	rest := strings.TrimLeft(l, "@")
	idx := strings.Index(rest, "//")
	if idx <= 0 {
		return pkgInfo
	}
	repo := rest[:idx]
	afterSlash := rest[idx+2:]

	pkgPath := afterSlash
	if i := strings.Index(pkgPath, ":"); i != -1 {
		pkgPath = pkgPath[:i]
	}

	if i := strings.LastIndexAny(repo, "~+"); i != -1 && i < len(repo)-1 {
		repo = repo[i+1:]
	}

	v, ok := r.lookup[repo]
	if !ok {
		return pkgInfo
	}

	pkgInfo.Name = v.Name
	if pkgPath != "" {
		pkgInfo.Name = v.Name + "/" + pkgPath
	}
	pkgInfo.Version = v.Version
	return pkgInfo
}
