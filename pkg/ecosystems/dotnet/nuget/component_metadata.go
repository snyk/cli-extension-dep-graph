package nuget

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

const (
	// sha512SidecarExt is the file NuGet writes beside each .nupkg it extracts
	// into a global packages folder: the base64 SHA-512 of the .nupkg itself.
	sha512SidecarExt = ".nupkg.sha512"
	// nupkgMetadataFile records, among other things, the service index of the
	// feed the package came from.
	nupkgMetadataFile = ".nupkg.metadata"

	nugetOrgServiceIndex  = "https://api.nuget.org/v3/index.json"
	nugetOrgFlatContainer = "https://api.nuget.org/v3-flatcontainer/"

	// assetsLibraryTypePackage marks a libraries entry restored from a feed, as
	// opposed to a project reference.
	assetsLibraryTypePackage = "package"

	// A base64 SHA-512 is 88 bytes and a real .nupkg.metadata a few hundred;
	// anything larger is not what NuGet wrote.
	maxSidecarBytes  = 1 << 10
	maxMetadataBytes = 1 << 20

	logFieldFile = "file"
)

var errNotRegularFile = errors.New("not a regular file")

// artifact is one .nupkg on disk: dir/stem.nupkg, with NuGet's sidecars
// beside it. Every label a node gets describes this one file.
type artifact struct {
	dir  string
	stem string
}

func (a artifact) path(suffix string) string { return filepath.Join(a.dir, a.stem+suffix) }

// componentLabeler attaches component-metadata labels for one scan. It exists
// only when --include-component-metadata is set; a nil labeler means the flag
// is off, and the graph is left exactly as built.
//
// It never touches the network. A feed other than nuget.org is labeled with
// its service index URL, as snyk-nuget-plugin does, rather than fetching the
// index for the file URL: the source comes from a file in the scanned
// repository, so fetching it would let a repository make the scanner request
// any URL it names.
type componentLabeler struct {
	log logger.Logger
	// labels caches each artifact's labels, since the same package recurs
	// across frameworks and projects and hashing a .nupkg is not free.
	labels map[labelKey]componentmetadata.Labels
}

type labelKey struct {
	artifact
	withURL bool
}

func newComponentLabeler(log logger.Logger) *componentLabeler {
	return &componentLabeler{log: log, labels: make(map[labelKey]componentmetadata.Labels)}
}

// labelAssetsGraph labels a PackageReference project's graph from the global
// packages folders its restore used, searched in the order the assets file
// lists them, as NuGet does.
//
// Only libraries of type package are labeled: a project reference can share a
// published package's name and version, and has no .nupkg of its own. A
// relative folder is skipped: NuGet always records absolute ones, and a
// relative one would resolve against the working directory, which the scanned
// repository controls.
func (c *componentLabeler) labelAssetsGraph(ctx context.Context, graph *godepgraph.DepGraph, assets *projectAssets) {
	if c == nil {
		return
	}

	folders := make([]string, 0, assets.PackageFolders.Len())
	for _, folder := range assets.PackageFolders.Keys() {
		if filepath.IsAbs(folder) {
			folders = append(folders, folder)
		}
	}

	labelNodes(graph, func(name, version string) componentmetadata.Labels {
		if assets.Libraries[name+"/"+version].Type != assetsLibraryTypePackage {
			return nil
		}

		found, ok := locateGlobalPackage(folders, name, version)
		if !ok {
			return nil
		}

		return c.artifactLabels(ctx, labelKey{artifact: found, withURL: true}, name, version)
	})
}

// labelFrameworkGraph labels a packages.config or project.json project's graph
// from its packages folder, with the .nupkg's hash only. NuGet writes
// .nupkg.metadata only when it extracts into the v3 global packages folder
// (NuGet.Client's PackageExtractor.InstallFromSourceAsync), never into a
// packages.config folder, so there is no recorded feed to name. Falling back
// to the nuget.config sources is a follow-up.
//
// Only installed packages are looked up: a node for a package that is not
// installed names no file on disk.
func (c *componentLabeler) labelFrameworkGraph(
	ctx context.Context,
	graph *godepgraph.DepGraph,
	installed *packageSet,
	packagesFolder string,
) {
	if c == nil {
		return
	}

	labelNodes(graph, func(name, version string) componentmetadata.Labels {
		pkg, ok := installed.get(name)
		if !ok || pkg.name != name || pkg.version != version || !safePathSegments(name, version) {
			return nil
		}

		found := artifact{dir: packageDir(packagesFolder, pkg), stem: name + "." + version}

		return c.artifactLabels(ctx, labelKey{artifact: found}, name, version)
	})
}

// labelNodes applies labelsOf's labels to each package node. It runs over the
// built graph because both graph builders reproduce upstream's walk exactly,
// and labeling is no part of that walk.
//
// Only a package's own node, whose ID is pkgNodeID of its name and version,
// is labeled. That leaves out the root, which is the project, and every
// pruned stub, whose ID carries prunedNodeSuffix: its full node is in the same
// graph and carries the labels. snyk-mvn-plugin leaves its pruned nodes the
// same way, and sbom-export folds a pruned stub into the full node.
func labelNodes(graph *godepgraph.DepGraph, labelsOf func(name, version string) componentmetadata.Labels) {
	pkgs := make(map[string]godepgraph.PkgInfo, len(graph.Pkgs))
	for _, pkg := range graph.Pkgs {
		pkgs[pkg.ID] = pkg.Info
	}

	for i := range graph.Graph.Nodes {
		node := &graph.Graph.Nodes[i]

		info, ok := pkgs[node.PkgID]
		if !ok || node.NodeID == graph.Graph.RootNodeID || node.NodeID != pkgNodeID(info.Name, info.Version) {
			continue
		}

		labelsOf(info.Name, info.Version).ApplyTo(node)
	}
}

// locateGlobalPackage finds a package in a global packages folder layout
// (<folder>/<id>/<version>/, lowercased). The folder holding the .nupkg.sha512
// wins; failing that, the first holding the .nupkg, which is then hashed.
// Everything labeled comes from that one folder, so the hash and the URL
// describe the same file.
func locateGlobalPackage(folders []string, name, version string) (artifact, bool) {
	id, ver := strings.ToLower(name), strings.ToLower(version)
	if !safePathSegments(id, ver) {
		return artifact{}, false
	}

	candidates := make([]artifact, 0, len(folders))
	for _, folder := range folders {
		candidates = append(candidates, artifact{dir: filepath.Join(folder, id, ver), stem: id + "." + ver})
	}

	for _, suffix := range []string{sha512SidecarExt, nupkgExt} {
		for _, candidate := range candidates {
			if isRegularFile(candidate.path(suffix)) {
				return candidate, true
			}
		}
	}

	return artifact{}, false
}

// safePathSegments rejects names that would step outside the package folder.
// NuGet ids and versions never contain separators, but these come from files
// in the scanned repository.
func safePathSegments(segments ...string) bool {
	for _, s := range segments {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `/\`) {
			return false
		}
	}

	return true
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// artifactLabels returns the hash and, if asked, the distribution URL for one
// .nupkg.
func (c *componentLabeler) artifactLabels(ctx context.Context, key labelKey, name, version string) componentmetadata.Labels {
	if cached, ok := c.labels[key]; ok {
		return cached
	}

	labels := componentmetadata.Labels{}
	c.addHash(ctx, labels, key.artifact)

	if key.withURL {
		if source, ok := c.feedSource(ctx, key.artifact); ok {
			labels.AddDistributionURL(distributionURL(source, name, version))
		}
	}

	c.labels[key] = labels

	return labels
}

// addHash prefers the .nupkg.sha512 NuGet wrote, and hashes the .nupkg only
// when that is absent or unusable. project.assets.json's libraries[*].sha512
// is never used: it is the package's content hash, which differs from the
// file's for a signed package.
func (c *componentLabeler) addHash(ctx context.Context, labels componentmetadata.Labels, a artifact) {
	if sidecar, err := readRegularFile(a.path(sha512SidecarExt), maxSidecarBytes); err == nil {
		if labels.AddBase64Hash("sha512", string(sidecar)) {
			return
		}

		c.log.Debug(ctx, "Ignoring a .nupkg.sha512 that is not a base64 SHA-512",
			logger.Attr(logFieldFile, a.path(sha512SidecarExt)))
	}

	digest, err := fileSHA512Hex(ctx, a.path(nupkgExt))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.log.Debug(ctx, "Could not hash a .nupkg", logger.Attr(logFieldFile, a.path(nupkgExt)), logger.Err(err))
		}

		return
	}

	labels.AddHash("sha512", digest)
}

// feedSource reads the feed a package was restored from.
func (c *componentLabeler) feedSource(ctx context.Context, a artifact) (string, bool) {
	path := filepath.Join(a.dir, nupkgMetadataFile)

	content, err := readRegularFile(path, maxMetadataBytes)
	if err != nil {
		return "", false
	}

	var metadata struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(content, &metadata); err != nil {
		c.log.Debug(ctx, "Ignoring an unparseable .nupkg.metadata", logger.Attr(logFieldFile, path), logger.Err(err))
		return "", false
	}

	return metadata.Source, metadata.Source != ""
}

// distributionURL is the .nupkg's URL on nuget.org, whose layout is known, or
// the service index of any other feed, the best package-level URL there is
// without a request. Labels.AddDistributionURL sanitizes it, and drops it for
// a local or UNC folder feed.
func distributionURL(source, name, version string) string {
	index, ok := componentmetadata.SanitizeURL(source)
	if !ok || !strings.EqualFold(index, nugetOrgServiceIndex) {
		return source
	}

	id, ver := url.PathEscape(strings.ToLower(name)), url.PathEscape(strings.ToLower(version))

	return nugetOrgFlatContainer + id + "/" + ver + "/" + id + "." + ver + nupkgExt
}

// openRegularFile opens path only if it is a regular file, checked before
// opening (a FIFO would block the open) and again on the opened file. A
// device such as /dev/zero would otherwise be read without end.
func openRegularFile(path string) (*os.File, error) {
	if info, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("checking %s: %w", path, err)
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, errNotRegularFile)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, errNotRegularFile)
	}

	return f, nil
}

// readRegularFile reads a small file, failing for one larger than limit.
func readRegularFile(path string, limit int64) ([]byte, error) {
	f, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}

	return content, nil
}

// fileSHA512Hex hashes a regular file, stopping when ctx is done.
func fileSHA512Hex(ctx context.Context, path string) (string, error) {
	f, err := openRegularFile(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(h, ctxReader{ctx: ctx, r: f}); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ctxReader fails its next read once ctx is done.
type ctxReader struct {
	ctx context.Context //nolint:containedctx // scoped to one io.Copy
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, fmt.Errorf("reading: %w", err)
	}

	n, err := c.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("reading: %w", err)
	}

	return n, err //nolint:wrapcheck // io.EOF must reach io.Copy unwrapped
}
