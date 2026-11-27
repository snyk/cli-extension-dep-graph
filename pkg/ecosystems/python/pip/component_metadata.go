package pip

import (
	"strings"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
)

// GraphOption configures ToDependencyGraph.
type GraphOption func(*graphOptions)

type graphOptions struct {
	componentMetadata bool
	// unlabelled holds normalized names that get no component metadata.
	unlabelled map[string]bool
}

// WithComponentMetadata labels each node with the hashes and URL of the
// archive pip picked for it, for --include-component-metadata.
func WithComponentMetadata() GraphOption {
	return func(o *graphOptions) { o.componentMetadata = true }
}

// WithoutComponentMetadataFor leaves the named packages unlabelled, for
// manifest entries whose source is not the archive pip reports, such as a
// Pipfile VCS entry that pip resolved by name from an index.
func WithoutComponentMetadataFor(names ...string) GraphOption {
	return func(o *graphOptions) {
		if o.unlabelled == nil {
			o.unlabelled = make(map[string]bool, len(names))
		}
		for _, n := range names {
			o.unlabelled[normalizePackageName(n)] = true
		}
	}
}

// componentLabels describes the exact file pip picked on this machine, so two
// machines may label one requirements file differently. That is deliberate:
// unlike poetry and uv, which choose among the files a lockfile lists, the
// report names the one archive pip would install.
//
// Only archive installs are labeled. A VCS or directory install's URL names
// a repository or folder rather than a file, and has no archive hash. A local
// archive keeps its hash; SanitizeURL rejects its file: URL.
func (item *InstallItem) componentLabels() componentmetadata.Labels {
	labels := componentmetadata.Labels{}
	di := item.DownloadInfo
	if di == nil || di.ArchiveInfo == nil {
		return labels
	}
	for alg, digest := range di.ArchiveInfo.Hashes {
		labels.AddHash(alg, digest)
	}
	if len(di.ArchiveInfo.Hashes) == 0 {
		if alg, digest, ok := strings.Cut(di.ArchiveInfo.Hash, "="); ok {
			labels.AddHash(alg, digest)
		}
	}
	labels.AddDistributionURL(di.URL)
	return labels
}
