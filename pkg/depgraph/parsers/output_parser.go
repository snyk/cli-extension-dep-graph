package parsers

type OutputParser interface {
	ParseOutput([]byte) ([]DepGraphOutput, error)
}
