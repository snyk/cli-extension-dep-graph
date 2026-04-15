package parsers

// DepGraphOutput represents a parsed dependency graph output.
type DepGraphOutput struct {
	NormalisedTargetFile string
	TargetFileFromPlugin *string
	TargetRuntime        *string
	Target               []byte
	DepGraph             []byte
	Workspace            []byte
	Error                []byte
}
