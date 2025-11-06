package parsers

// OutputParser is an interface for parsing dependency graph output.
type OutputParser interface {
	ParseOutput([]byte) ([]DepGraphOutput, error)
}
