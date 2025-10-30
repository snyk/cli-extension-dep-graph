package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
)

type JSONLOutputParser struct {
}

var _ OutputParser = (*JSONLOutputParser)(nil)

func NewJSONL() OutputParser {
	return &JSONLOutputParser{}
}

type jsonLine struct {
	DepGraph             json.RawMessage `json:"depGraph"`
	NormalisedTargetFile string          `json:"normalisedTargetFile"`
	TargetFileFromPlugin *string         `json:"targetFileFromPlugin"`
	Target               json.RawMessage `json:"target"`
}

func (j *JSONLOutputParser) ParseOutput(data []byte) ([]DepGraphOutput, error) {
	var depGraphList []DepGraphOutput

	scanner := bufio.NewScanner(bytes.NewReader(data))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024*1024) // 1GB max token size
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var parsed jsonLine
		if err := json.Unmarshal(line, &parsed); err != nil {
			return nil, err
		}

		depGraphList = append(depGraphList, DepGraphOutput{
			NormalisedTargetFile: parsed.NormalisedTargetFile,
			TargetFileFromPlugin: parsed.TargetFileFromPlugin,
			Target:               parsed.Target,
			DepGraph:             parsed.DepGraph,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return depGraphList, nil
}
