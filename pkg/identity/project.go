package identity

// ProjectDescriptor contains the complete description of a project,
// including its identity and build arguments.
type ProjectDescriptor struct {
	Identity ProjectIdentity
}

// ProjectIdentity defines the core identifying characteristics of a project.
type ProjectIdentity struct {
	// Type specifies the project type (e.g., "npm", "maven", "pip")
	Type string
	// BaseNameOverride allows overriding the default base name for the project
	BaseNameOverride *string
	// TargetFile specifies the manifest or build file for the project
	TargetFile *string
	// TargetRuntime specifies the runtime environment for the project
	TargetRuntime *string
}

// GetTargetFile extracts the target file from a ProjectDescriptor.
// Returns an empty string if TargetFile is nil.
func (pd ProjectDescriptor) GetTargetFile() string {
	if pd.Identity.TargetFile != nil {
		return *pd.Identity.TargetFile
	}
	return ""
}
