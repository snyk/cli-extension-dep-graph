package cocoapods

import (
	"fmt"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

// Label keys preserved verbatim from @snyk/snyk-cocoapods-plugin so the
// resulting dep-graphs are byte-compatible with the legacy plugin's
// output. Downstream consumers (Snyk policy engine, vuln-DB lookups)
// rely on these exact key names.
const (
	labelChecksum   = "checksum"
	labelRepository = "repository"

	labelExternalSourceGit     = "externalSourceGit"
	labelExternalSourcePath    = "externalSourcePath"
	labelExternalSourceTag     = "externalSourceTag"
	labelExternalSourceCommit  = "externalSourceCommit"
	labelExternalSourceBranch  = "externalSourceBranch"
	labelExternalSourcePodspec = "externalSourcePodspec"

	labelCheckoutOptionsGit     = "checkoutOptionsGit"
	labelCheckoutOptionsPath    = "checkoutOptionsPath"
	labelCheckoutOptionsTag     = "checkoutOptionsTag"
	labelCheckoutOptionsCommit  = "checkoutOptionsCommit"
	labelCheckoutOptionsBranch  = "checkoutOptionsBranch"
	labelCheckoutOptionsPodspec = "checkoutOptionsPodspec"
)

// BuildDepGraph converts a parsed Podfile.lock into a Snyk dep-graph.
//
// Node identity = root spec name (the part before the first '/').
// CocoaPods guarantees one resolved version per root spec, so subspecs
// like AFNetworking/NSURLConnection collapse onto the AFNetworking node
// — this matches the legacy plugin's `nodeIdForPkgInfo` strategy.
//
// rootName/rootVersion describe the project being scanned, not a pod.
// Direct entries from DEPENDENCIES are attached to the root node;
// transitive edges are inferred from each PODS entry's nested dep list.
func BuildDepGraph(lock *Lockfile, rootName, rootVersion string) (*depgraph.DepGraph, error) {
	if lock == nil {
		return nil, fmt.Errorf("lockfile is nil")
	}

	pkgManager := &depgraph.PkgManager{
		Name:         pkgManagerName,
		Version:      lockfileCocoapodsVersion(lock),
		Repositories: repositoriesFor(lock),
	}

	builder, err := depgraph.NewBuilder(pkgManager, &depgraph.PkgInfo{
		Name:    rootName,
		Version: rootVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}
	rootNodeID := builder.GetRootNode().NodeID

	// Pass 1: add every PODS entry as a node keyed by root spec name.
	// Multiple subspecs of the same root collapse onto the same node;
	// the *first* PODS appearance wins for labels/version (the root
	// spec entry itself is always emitted by CocoaPods first, so this
	// is the right choice in practice).
	//
	// We also accumulate each node's outgoing edges as PkgInfo lists so
	// the second pass can resolve them to node IDs after all nodes
	// exist.
	addedNodes := make(map[string]struct{}, len(lock.Pods))
	allDeps := make(map[string][]PkgInfo, len(lock.Pods))

	for _, entry := range lock.Pods {
		spec, err := ParseSpecification(entry.Spec)
		if err != nil {
			return nil, fmt.Errorf("PODS entry: %w", err)
		}
		nodeID := RootSpecName(spec.Name)

		if _, seen := addedNodes[nodeID]; !seen {
			labels := labelsForPod(lock, spec.Name)
			builder.AddNode(nodeID,
				&depgraph.PkgInfo{Name: nodeID, Version: spec.Version},
				depgraph.WithNodeInfo(&depgraph.NodeInfo{Labels: labels}),
			)
			addedNodes[nodeID] = struct{}{}
		}

		for _, depStr := range entry.Deps {
			depInfo, err := ParseDependency(depStr)
			if err != nil {
				return nil, fmt.Errorf("PODS entry %q: %w", entry.Spec, err)
			}
			allDeps[nodeID] = append(allDeps[nodeID], depInfo)
		}
	}

	// Pass 2: connect direct dependencies from the manifest
	// (DEPENDENCIES section) to the root node.
	for _, depStr := range lock.Dependencies {
		depInfo, err := ParseDependency(depStr)
		if err != nil {
			return nil, fmt.Errorf("DEPENDENCIES entry: %w", err)
		}
		depNodeID := RootSpecName(depInfo.Name)
		if _, ok := addedNodes[depNodeID]; !ok {
			// Skip phantom direct deps that have no PODS entry. Real
			// lockfiles always carry one, but tolerate gracefully so
			// malformed input fails loud (later) rather than crashing.
			continue
		}
		if err := builder.ConnectNodes(rootNodeID, depNodeID); err != nil {
			return nil, fmt.Errorf("connecting root → %s: %w", depNodeID, err)
		}
	}

	// Pass 3: connect transitive edges (one per PODS entry).
	// Mirrors legacy behavior: edges pointing at pods without their
	// own PODS entry are silently dropped (platform-specific subspecs
	// not pulled in by this integration's targets).
	for nodeID, deps := range allDeps {
		for _, dep := range deps {
			depNodeID := RootSpecName(dep.Name)
			if depNodeID == nodeID {
				// Subspec referencing its own root — would be a self-edge.
				continue
			}
			if _, ok := addedNodes[depNodeID]; !ok {
				continue
			}
			if err := builder.ConnectNodes(nodeID, depNodeID); err != nil {
				return nil, fmt.Errorf("connecting %s → %s: %w", nodeID, depNodeID, err)
			}
		}
	}

	return builder.Build(), nil
}

// labelsForPod produces the NodeInfo labels for one pod, looking up the
// checksum, optional repository, optional external source, and optional
// checkout options by the pod's root spec name.
//
// Nil/empty values are omitted so the resulting label map round-trips
// through JSON without producing explicit null fields (legacy plugin
// strips nulls explicitly; we never insert them in the first place).
// Returns nil rather than an empty map when no labels apply, so the
// dep-graph JSON omits the "info" block entirely for plain pods.
func labelsForPod(lock *Lockfile, podName string) map[string]string {
	root := RootSpecName(podName)
	labels := map[string]string{}

	if cs := lock.SpecChecksums[root]; cs != "" {
		labels[labelChecksum] = cs
	}

	if repo := repositoryForPod(lock, root); repo != "" {
		labels[labelRepository] = repo
	}

	if ext, ok := lock.ExternalSources[root]; ok {
		putIfSet(labels, labelExternalSourceGit, ext.Git)
		putIfSet(labels, labelExternalSourcePath, ext.Path)
		putIfSet(labels, labelExternalSourceTag, ext.Tag)
		putIfSet(labels, labelExternalSourceCommit, ext.Commit)
		putIfSet(labels, labelExternalSourceBranch, ext.Branch)
		putIfSet(labels, labelExternalSourcePodspec, ext.Podspec)
	}

	if co, ok := lock.CheckoutOptions[root]; ok {
		putIfSet(labels, labelCheckoutOptionsGit, co.Git)
		putIfSet(labels, labelCheckoutOptionsPath, co.Path)
		putIfSet(labels, labelCheckoutOptionsTag, co.Tag)
		putIfSet(labels, labelCheckoutOptionsCommit, co.Commit)
		putIfSet(labels, labelCheckoutOptionsBranch, co.Branch)
		putIfSet(labels, labelCheckoutOptionsPodspec, co.Podspec)
	}

	if len(labels) == 0 {
		return nil
	}
	return labels
}

func putIfSet(m map[string]string, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// repositoryForPod returns the SPEC REPOS key (name or URL) under which
// the named pod is listed. Returns empty string if SPEC REPOS is absent
// (older Podfile.lock) or the pod is not registered to any repo.
func repositoryForPod(lock *Lockfile, rootName string) string {
	for repo, pods := range lock.SpecRepos {
		for _, p := range pods {
			if p == rootName {
				return repo
			}
		}
	}
	return ""
}

// repositoriesFor lifts the SPEC REPOS section keys into the dep-graph's
// PkgManager.Repositories list. Order is not significant in the schema
// and Go's map iteration is intentionally randomised — callers that
// need deterministic ordering should sort on the consumer side. The
// legacy TypeScript plugin had the same non-determinism.
func repositoriesFor(lock *Lockfile) []depgraph.Repository {
	if len(lock.SpecRepos) == 0 {
		return nil
	}
	repos := make([]depgraph.Repository, 0, len(lock.SpecRepos))
	for name := range lock.SpecRepos {
		repos = append(repos, depgraph.Repository{Alias: name})
	}
	return repos
}

// lockfileCocoapodsVersion returns the COCOAPODS field or "unknown" when
// the lockfile predates that section (CocoaPods began writing it in v1).
func lockfileCocoapodsVersion(lock *Lockfile) string {
	if lock.CocoapodsVersion == "" {
		return defaultCocoapodsVersion
	}
	return lock.CocoapodsVersion
}
