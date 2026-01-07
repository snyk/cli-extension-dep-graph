package parsers

// DepGraphOutput represents a parsed dependency graph output.
type DepGraphOutput struct {
	NormalisedTargetFile string
	TargetFileFromPlugin *string
	Target               []byte
	DepGraph             []byte
	Error                []byte
}
