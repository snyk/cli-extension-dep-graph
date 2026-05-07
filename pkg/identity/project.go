package identity

// ProjectDescriptor contains the complete description of a project,
// including its identity and build arguments.
type ProjectDescriptor struct {
	Identity ProjectIdentity `json:"identity"`
}

// ProjectIdentity defines the core identifying characteristics of a project.
type ProjectIdentity struct {
	// ProjectType specifies the project type (e.g., "npm", "maven", "pip")
	ProjectType string `json:"type,omitempty"`
	// TargetFile specifies the manifest or build file for the project
	TargetFile *string `json:"targetFile,omitempty"`
	// TargetRuntime specifies the runtime environment for the project
	TargetRuntime *string `json:"targetRuntime,omitempty"`
	// RootComponentName specifies the component's name that is at the root of the project
	RootComponentName string `json:"rootComponentName,omitempty"`
	// Legacy holds fields that exist solely to bridge legacy CLI quirks. New plugin
	// authors should leave this nil.
	Legacy *LegacyIdentity `json:"legacy,omitempty"`
}

// LegacyIdentity carries fields that exist solely to bridge quirks of the legacy Snyk CLI.
// New plugins do not need to populate this.
type LegacyIdentity struct {
	// Target carries scan-source metadata (Git remote URL, container image info) when
	// available. Downstream Snyk CLI consumers receive it via the workflow.Data `target`
	// metadata key and use it to associate scans with their source project.
	Target []byte `json:"target,omitempty"`
	// SuppressTargetFileFromPlugin tells downstream emission to OMIT the
	// MetaKeyTargetFileFromPlugin workflow.Data key. Under certain conditions, the
	// legacy CLI does not set plugin.targetFile, and downstream consumers treat that
	// absence as a signal when constructing API payloads. We have to preserve it for
	// parity.
	SuppressTargetFileFromPlugin bool `json:"suppressTargetFileFromPlugin,omitempty"`
}

// GetTargetFile extracts the target file from a ProjectDescriptor.
// Returns an empty string if TargetFile is nil.
func (pd *ProjectDescriptor) GetTargetFile() string {
	if pd.Identity.TargetFile != nil {
		return *pd.Identity.TargetFile
	}
	return ""
}

// GetTargetFileForPlugin returns the value that downstream consumers should use for the
// legacy CLI's plugin.targetFile semantic (workflow.Data MetaKeyTargetFileFromPlugin or
// the registry API's targetFileFromPlugin field). Returns nil for legacy-CLI project
// types whose snyk plugin would have suppressed plugin.targetFile (npm/yarn/pnpm
// non-workspace, maven, sbt, rubygems, requirements.txt). New plugins return
// Identity.TargetFile unchanged (no Legacy substruct, no suppression).
func (pd *ProjectDescriptor) GetTargetFileForPlugin() *string {
	if pd.Identity.Legacy != nil && pd.Identity.Legacy.SuppressTargetFileFromPlugin {
		return nil
	}
	return pd.Identity.TargetFile
}
