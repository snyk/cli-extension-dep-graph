package gradle

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/package-url/packageurl-go"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"golang.org/x/sync/errgroup"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

const (
	// normaliseConcurrency caps in-flight package lookups to avoid overwhelming
	// the Packages API.
	normaliseConcurrency = 100

	// Logging attribute keys used consistently across the normalize deps implementation.
	logAttrSha1 = "sha1"
)

// NormalizeDepsPostHook is the post-hook signature accepted by the Gradle
// plugin. It rewrites SCA results in place using canonical Maven coordinates
// resolved by SHA1 via the Snyk Packages API.
type NormalizeDepsPostHook = func(
	ctx context.Context,
	log logger.Logger,
	results []ecosystems.SCAResult,
	options *ecosystems.SCAPluginOptions,
) []ecosystems.SCAResult

// packageLookuper is the minimal interface the post-hook needs from the Snyk
// API client. It is satisfied by *snykclient.SnykClient and is extracted so
// tests can substitute a fake.
type packageLookuper interface {
	LookupMavenPackage(ctx context.Context, q snykclient.MavenPackageQuery) (string, error)
}

// mavenCoords captures the Maven GAV triple used both for the API lookup
// fallback and for rewriting the dep-graph after a canonical purl is returned.
type mavenCoords struct {
	groupID  string
	artifact string
	version  string
}

// NewNormalizeDepsPostHook returns a post-hook that rewrites Gradle SCA
// results using canonical Maven coordinates fetched from the Snyk Packages
// API.
//
// httpClient and apiBaseURL must originate from the GAF networking layer so
// that authentication, retries, and user-agent headers are applied to outbound
// requests. orgID is required: the Packages API is gated by an authenticated
// org context, and we no-op (returning the input unchanged) when it is empty.
func NewNormalizeDepsPostHook(httpClient *http.Client, apiBaseURL, orgID string) NormalizeDepsPostHook {
	client := snykclient.NewSnykClient(httpClient, apiBaseURL, orgID)
	return newNormalizeDepsPostHookWithClient(client, orgID)
}

// newNormalizeDepsPostHookWithClient is the test-friendly seam: it accepts an
// already-constructed lookuper and the org ID used for the empty-org guard.
func newNormalizeDepsPostHookWithClient(client packageLookuper, orgID string) NormalizeDepsPostHook {
	return func(
		ctx context.Context,
		log logger.Logger,
		results []ecosystems.SCAResult,
		options *ecosystems.SCAPluginOptions,
	) []ecosystems.SCAResult {
		if log == nil {
			log = logger.Nop()
		}

		if orgID == "" {
			log.Debug(ctx, "gradle: normalize-deps requested but no org id available; skipping normalisation")
			return results
		}

		lookups := collectShaLookups(results)
		log.Debug(ctx, "gradle: collected unique SHA1 lookups for normalisation",
			logger.Attr("count", len(lookups)))

		var canonicalBySha1 map[string]mavenCoords
		if len(lookups) > 0 {
			var failures int
			canonicalBySha1, failures = resolveCanonicalCoords(ctx, log, client, lookups)
			if failures > 0 {
				// Info, not Error: per-SHA1 failures are non-fatal — nodes
				// without a canonical mapping are kept as-is, matching the
				// requested partial-rewrite semantics.
				log.Info(ctx, "gradle: some dependency normalisation lookups failed; affected nodes left unchanged",
					logger.Attr("failures", failures),
					logger.Attr("total", len(lookups)))
			}
		}

		includeProvenance := options != nil && options.Global.IncludeProvenance
		for i := range results {
			if results[i].DepGraph == nil {
				continue
			}
			rewritten, err := rewriteDepGraph(results[i].DepGraph, canonicalBySha1, includeProvenance)
			if err != nil {
				log.Info(ctx, "gradle: dep-graph rewrite produced an invalid graph; leaving result unchanged",
					logger.Err(err))
				continue
			}
			results[i].DepGraph = rewritten
		}

		return results
	}
}

// collectShaLookups walks every dep-graph and returns a map keyed by SHA1
// containing the original Maven coordinates parsed from each unique purl.
//
// Original coordinates are preserved because the Packages API accepts them as
// a fallback alongside the SHA1. Pkgs without a parseable purl, without a SHA1
// qualifier, or that are not pkg:maven are skipped — there is nothing to
// normalise.
func collectShaLookups(results []ecosystems.SCAResult) map[string]mavenCoords {
	lookups := make(map[string]mavenCoords)
	for _, result := range results {
		if result.DepGraph == nil {
			continue
		}
		for _, pkg := range result.DepGraph.Pkgs {
			sha1, coords, ok := parseMavenPurl(pkg.Info.PackageURL)
			if !ok {
				continue
			}
			if _, exists := lookups[sha1]; exists {
				continue
			}
			lookups[sha1] = coords
		}
	}
	return lookups
}

// parseMavenPurl extracts the SHA1 qualifier and group/artifact/version triple
// from a pkg:maven purl. It returns ok=false for any non-maven purl, any purl
// without a sha1 checksum qualifier, or any malformed input.
func parseMavenPurl(purlString string) (sha1 string, coords mavenCoords, ok bool) {
	if purlString == "" {
		return "", mavenCoords{}, false
	}
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return "", mavenCoords{}, false
	}
	if purl.Type != packageurl.TypeMaven {
		return "", mavenCoords{}, false
	}
	qualifiers := purl.Qualifiers.Map()
	checksum := qualifiers["checksum"]
	const sha1Prefix = "sha1:"
	if len(checksum) <= len(sha1Prefix) || checksum[:len(sha1Prefix)] != sha1Prefix {
		return "", mavenCoords{}, false
	}
	return checksum[len(sha1Prefix):], mavenCoords{
		groupID:  purl.Namespace,
		artifact: purl.Name,
		version:  purl.Version,
	}, true
}

// resolveCanonicalCoords issues one lookup per unique SHA1, returning a map
// from SHA1 to the canonical Maven coordinates reported by the Packages API.
//
// All per-SHA1 failures are treated as soft failures — including context
// cancellation, which causes in-flight lookups to return errors that are
// counted the same as any other API failure. Unmapped entries are simply absent
// from the returned map, which causes the rewrite pass to leave the
// corresponding nodes untouched. The failure count is returned alongside the
// map so callers can surface a summary warning.
func resolveCanonicalCoords(
	ctx context.Context,
	log logger.Logger,
	client packageLookuper,
	lookups map[string]mavenCoords,
) (map[string]mavenCoords, int) {
	canonical := make(map[string]mavenCoords, len(lookups))
	var (
		mu       sync.Mutex
		failures atomic.Int64
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(normaliseConcurrency)

	for sha1, coords := range lookups {
		group.Go(func() error {
			canonicalCoords, ok := resolveOne(groupCtx, log, client, sha1, coords)
			if !ok {
				failures.Add(1)
				return nil
			}
			mu.Lock()
			canonical[sha1] = canonicalCoords
			mu.Unlock()
			return nil
		})
	}
	_ = group.Wait()

	return canonical, int(failures.Load())
}

// resolveOne performs a single SHA1 lookup and parses the returned purl.
// ok=false signals "no rewrite for this SHA1" — either the API had no record,
// the request failed, or the response purl was unparseable. All such cases are
// recoverable by leaving the original coordinates in place.
func resolveOne(
	ctx context.Context,
	log logger.Logger,
	client packageLookuper,
	sha1 string,
	original mavenCoords,
) (mavenCoords, bool) {
	purlString, err := client.LookupMavenPackage(ctx, snykclient.MavenPackageQuery{
		SHA1:     sha1,
		GroupID:  original.groupID,
		Artifact: original.artifact,
		Version:  original.version,
	})
	if err != nil {
		log.Debug(ctx, "gradle: package lookup failed",
			logger.Attr(logAttrSha1, sha1),
			logger.Err(err))
		return mavenCoords{}, false
	}
	if purlString == "" {
		log.Debug(ctx, "gradle: no canonical mapping available for SHA1",
			logger.Attr(logAttrSha1, sha1))
		return mavenCoords{}, false
	}
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		log.Debug(ctx, "gradle: failed to parse canonical purl from API",
			logger.Attr(logAttrSha1, sha1),
			logger.Attr("purl", purlString),
			logger.Err(err))
		return mavenCoords{}, false
	}
	return mavenCoords{
		groupID:  purl.Namespace,
		artifact: purl.Name,
		version:  purl.Version,
	}, true
}

// rewriteDepGraph applies canonical Maven coordinates to a dep-graph in a
// dedupe-aware manner.
//
// The dep-graph is rewritten in three steps:
//  1. For every pkg whose purl carries a SHA1 that resolved to canonical
//     coordinates, produce a new pkg ID and updated PkgInfo. Two distinct
//     originals (e.g. different version strings of the same artifact) may
//     resolve to the same canonical pkg ID — duplicates are merged.
//  2. Every node referencing a rewritten pkg gets its PkgID updated. Node IDs
//     themselves are left untouched: they are opaque handles already used in
//     dep edges, and the suffixed forms used for pruned/constraint nodes must
//     remain unique.
//  3. When --include-provenance was not requested, every purl is stripped from
//     the final output. This matches the behavior of a non-provenance build
//     and avoids leaking the purls we synthesized solely to power this hook.
//
// BuildGraph is called on the result, which validates that every node PkgID
// still references a known pkg. An error from BuildGraph indicates a bug in
// the rewrite logic; callers should fall back to the original graph.
func rewriteDepGraph(
	dg *depgraph.DepGraph,
	canonicalBySha1 map[string]mavenCoords,
	includeProvenance bool,
) (*depgraph.DepGraph, error) {
	if dg == nil {
		return nil, nil
	}

	oldToNewPkgID := make(map[string]string, len(dg.Pkgs))
	newPkgs := make([]depgraph.Pkg, 0, len(dg.Pkgs))
	seenNewPkgID := make(map[string]int, len(dg.Pkgs))

	for _, pkg := range dg.Pkgs {
		newPkg, changed := rewritePkg(&pkg, canonicalBySha1)
		if changed {
			oldToNewPkgID[pkg.ID] = newPkg.ID
		}
		if !includeProvenance {
			newPkg.Info.PackageURL = ""
		}
		if existingIdx, ok := seenNewPkgID[newPkg.ID]; ok {
			// Merge: another original pkg has already produced this canonical
			// ID. Discard the duplicate but keep the redirection so nodes
			// pointing at this original are rewritten to the survivor below.
			oldToNewPkgID[pkg.ID] = newPkgs[existingIdx].ID
			continue
		}
		seenNewPkgID[newPkg.ID] = len(newPkgs)
		newPkgs = append(newPkgs, newPkg)
	}

	newNodes := make([]depgraph.Node, len(dg.Graph.Nodes))
	for i, node := range dg.Graph.Nodes {
		newNodes[i] = node

		// Find the longest matching base package ID that this node starts with
		var bestMatch string
		var bestReplacement string

		for oldPkgID, newPkgID := range oldToNewPkgID {
			if strings.HasPrefix(node.PkgID, oldPkgID) && len(oldPkgID) > len(bestMatch) {
				bestMatch = oldPkgID
				bestReplacement = newPkgID
			}
		}

		if bestMatch != "" {
			// Replace the matching prefix with the canonical ID, preserving any suffix
			suffix := node.PkgID[len(bestMatch):]
			newNodes[i].PkgID = bestReplacement + suffix
		}
	}

	out := &depgraph.DepGraph{
		SchemaVersion: dg.SchemaVersion,
		PkgManager:    dg.PkgManager,
		Pkgs:          newPkgs,
		Graph: depgraph.Graph{
			RootNodeID: dg.Graph.RootNodeID,
			Nodes:      newNodes,
		},
	}
	if err := out.BuildGraph(); err != nil {
		return nil, fmt.Errorf("rewritten dep-graph failed validation: %w", err)
	}
	return out, nil
}

// rewritePkg returns a copy of pkg with canonical Maven coordinates applied
// when a SHA1 mapping is available. changed indicates whether the pkg ID
// changed (used to decide whether to record a redirection for node rewriting).
//
// When the original purl had a SHA1 qualifier but no canonical mapping was
// found, the pkg is returned unchanged: this is the "leave the node as it
// was" behavior requested for unresolved SHA1s.
//
// The checksum qualifier is preserved on rewritten purls (as elsewhere in
// this plugin, the SHA1 is the source-of-truth artifact identity).
func rewritePkg(pkg *depgraph.Pkg, canonicalBySha1 map[string]mavenCoords) (depgraph.Pkg, bool) {
	sha1, _, ok := parseMavenPurl(pkg.Info.PackageURL)
	if !ok {
		return *pkg, false
	}
	canonical, found := canonicalBySha1[sha1]
	if !found {
		return *pkg, false
	}
	newName := fmt.Sprintf("%s:%s", canonical.groupID, canonical.artifact)
	newVersion := canonical.version

	// Create the canonical PURL using the packageurl library
	qualifiers := packageurl.Qualifiers{
		{Key: "checksum", Value: "sha1:" + sha1},
	}
	purl := packageurl.NewPackageURL(packageurl.TypeMaven, canonical.groupID, canonical.artifact, newVersion, qualifiers, "")
	newPurl := purl.ToString()
	return depgraph.Pkg{
		ID: fmt.Sprintf("%s@%s", newName, newVersion),
		Info: depgraph.PkgInfo{
			Name:       newName,
			Version:    newVersion,
			PackageURL: newPurl,
		},
	}, true
}
