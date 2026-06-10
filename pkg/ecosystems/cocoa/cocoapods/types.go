package cocoapods

// PluginName is the SCAPlugin identifier for the CocoaPods plugin.
const PluginName = "cocoapods"

// pkgManagerName is the dep-graph PkgManager.Name written into the dep
// graph itself. Matches the legacy @snyk/snyk-cocoapods-plugin output so
// downstream consumers (Snyk monitor/test ingestion) see the same value.
const pkgManagerName = "cocoapods"

const (
	defaultRootVersion        = "0.0.0"
	defaultCocoapodsVersion   = "unknown"
	lockfileName              = "Podfile.lock"
	manifestPodfile           = "Podfile"
	manifestPodfileRb         = "Podfile.rb"
	manifestCocoapodsPodfile  = "CocoaPods.podfile"
	manifestCocoapodsPodfileY = "CocoaPods.podfile.yaml"
)

// manifestPriority lists Podfile-equivalent manifest filenames in the
// order the legacy plugin probes them. The first one that exists in the
// lockfile directory wins for the project's TargetFile.
var manifestPriority = []string{
	manifestCocoapodsPodfileY,
	manifestCocoapodsPodfile,
	manifestPodfile,
	manifestPodfileRb,
}

// Lockfile mirrors the YAML structure of a Podfile.lock. Optional
// sections (SPEC REPOS, EXTERNAL SOURCES, CHECKOUT OPTIONS, PODFILE
// CHECKSUM, COCOAPODS) are not present in older lockfiles and decode to
// nil/empty values — every read site must handle the absence gracefully.
//
// PODS is a heterogeneous list of either bare specification strings
// (no transitive deps, e.g. "Expecta (1.0.5)") or single-key maps from
// specification string to a list of dependency strings (e.g.
// "React/Core (0.59.2)": ["yoga (= 0.59.2.React)"]). We decode each entry
// as yaml.Node and split on shape in the parser.
type Lockfile struct {
	Pods             []PodEntry                   `yaml:"PODS"`
	Dependencies     []string                     `yaml:"DEPENDENCIES"`
	SpecRepos        map[string][]string          `yaml:"SPEC REPOS,omitempty"`
	ExternalSources  map[string]ExternalSource    `yaml:"EXTERNAL SOURCES,omitempty"`
	CheckoutOptions  map[string]CheckoutOptions   `yaml:"CHECKOUT OPTIONS,omitempty"`
	SpecChecksums    map[string]string            `yaml:"SPEC CHECKSUMS"`
	PodfileChecksum  string                       `yaml:"PODFILE CHECKSUM,omitempty"`
	CocoapodsVersion string                       `yaml:"COCOAPODS,omitempty"`
}

// PodEntry is one element of the PODS list. Spec is the specification
// string ("Name (version)") and Deps is the list of dependency strings
// (empty when the pod is a bare leaf).
type PodEntry struct {
	Spec string
	Deps []string
}

// ExternalSource is the parsed value of an EXTERNAL SOURCES entry. The
// keys are written in the lockfile with leading colons (Ruby symbol
// syntax: `:git`, `:tag`, etc.) and we preserve that distinction so the
// resulting labels match the legacy plugin exactly.
type ExternalSource struct {
	Git     string `yaml:":git,omitempty"`
	Path    string `yaml:":path,omitempty"`
	Tag     string `yaml:":tag,omitempty"`
	Commit  string `yaml:":commit,omitempty"`
	Branch  string `yaml:":branch,omitempty"`
	Podspec string `yaml:":podspec,omitempty"`
}

// CheckoutOptions has the same shape as ExternalSource — same Ruby symbol
// keys, same meaning, written into a separate lockfile section.
type CheckoutOptions = ExternalSource
