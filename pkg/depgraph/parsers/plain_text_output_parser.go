package parsers

import (
	"bytes"
	"strings"
)

type PlainTextOutputParser struct {
}

var _ OutputParser = (*PlainTextOutputParser)(nil)

func NewPlainText() OutputParser {
	return &PlainTextOutputParser{}
}

var (
	jsonSeparatorEnd    = []byte("DepGraph end")
	jsonSeparatorData   = []byte("DepGraph data:")
	jsonSeparatorTarget = []byte("DepGraph target:")
)

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
				DepGraph:          depGraphJSON,
				DisplayTargetName: strings.TrimSpace(string(targetName)),
			}

			depGraphList = append(depGraphList, o)
		}
	}

	return depGraphList, nil

}
