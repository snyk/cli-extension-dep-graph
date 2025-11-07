package parsers

import (
	"bytes"
	"strings"
)

// PlainTextOutputParser parses plain text formatted dependency graph output.
type PlainTextOutputParser struct{}

var _ OutputParser = (*PlainTextOutputParser)(nil)

// NewPlainText creates a new plain text output parser.
func NewPlainText() OutputParser {
	return &PlainTextOutputParser{}
}

var (
	jsonSeparatorEnd    = []byte("DepGraph end")
	jsonSeparatorData   = []byte("DepGraph data:")
	jsonSeparatorTarget = []byte("DepGraph target:")
)

// ParseOutput parses plain text formatted dependency graph output.
func (p PlainTextOutputParser) ParseOutput(output []byte) ([]DepGraphOutput, error) {
	depGraphList := []DepGraphOutput{}

	separatedJSONRawData := bytes.Split(output, jsonSeparatorEnd)
	for i := range separatedJSONRawData {
		rawData := separatedJSONRawData[i]
		if bytes.Contains(rawData, jsonSeparatorData) {
			graphStartIndex := bytes.Index(rawData, jsonSeparatorData) + len(jsonSeparatorData)
			graphEndIndex := bytes.Index(rawData, jsonSeparatorTarget)
			targetNameStartIndex := graphEndIndex + len(jsonSeparatorTarget)
			targetNameEndIndex := len(rawData) - 1

			targetName := rawData[targetNameStartIndex:targetNameEndIndex]
			depGraphJSON := rawData[graphStartIndex:graphEndIndex]

			o := DepGraphOutput{
				DepGraph:             depGraphJSON,
				NormalisedTargetFile: strings.TrimSpace(string(targetName)),
			}

			depGraphList = append(depGraphList, o)
		}
	}

	return depGraphList, nil
}
