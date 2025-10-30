package parsers

type DepGraphOutput struct {
	NormalisedTargetFile string
	TargetFileFromPlugin *string
	Target               []byte
	DepGraph             []byte
}
