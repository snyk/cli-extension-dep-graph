//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

type ScanResultTarget struct {
	RemoteURL string `json:"remoteUrl"`
}

type ScanResultIdentity struct {
	Type       string            `json:"type"`
	TargetFile string            `json:"targetFile,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

type ScanResultFact struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

const depGraphKey = "depGraph"

// UnmarshalJSON implements custom JSON unmarshaling for ScanResultFact.
// When type is "depGraph", it unmarshals data directly into *depgraph.DepGraph.
func (f *ScanResultFact) UnmarshalJSON(data []byte) error {
	var scanResultRaw struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}

	if err := json.Unmarshal(data, &scanResultRaw); err != nil {
		return fmt.Errorf("failed to unmarshal ScanResultFact: %w", err)
	}

	f.Type = scanResultRaw.Type

	switch scanResultRaw.Type {
	case depGraphKey:
		var depGraph depgraph.DepGraph
		if err := json.Unmarshal(scanResultRaw.Data, &depGraph); err != nil {
			return fmt.Errorf("failed to unmarshal depGraph data: %w", err)
		}
		f.Data = &depGraph
	default:
		var v any
		if err := json.Unmarshal(scanResultRaw.Data, &v); err != nil {
			return fmt.Errorf("failed to unmarshal fact data: %w", err)
		}
		f.Data = v
	}

	return nil
}

type ScanResult struct {
	Name            string             `json:"name"`
	Policy          string             `json:"policy,omitempty"`
	Facts           []*ScanResultFact  `json:"facts"`
	Target          ScanResultTarget   `json:"target"`
	Identity        ScanResultIdentity `json:"identity"`
	TargetReference string             `json:"targetReference,omitempty"`
}

func (sr *ScanResult) DepGraphs() ([]*depgraph.DepGraph, error) {
	depGraphList := []*depgraph.DepGraph{}
	for _, fact := range sr.Facts {
		if fact.Type != depGraphKey {
			continue
		}

		// ScanResultFact.UnmarshalJSON deserializes fact.Data into *depgraph.DepGraph when type is "depGraph".
		depGraph, ok := fact.Data.(*depgraph.DepGraph)
		if !ok {
			return nil, fmt.Errorf("expected fact.Data to be *depgraph.DepGraph, got %T", fact.Data)
		}
		if depGraph == nil {
			return nil, fmt.Errorf("depGraph is nil for fact with type 'depGraph'")
		}

		depGraphList = append(depGraphList, depGraph)
	}
	return depGraphList, nil
}

type ConversionWarning struct {
	Type   string `json:"type"`
	BOMRef string `json:"bom_ref"`
	Msg    string `json:"msg"`
}

type SBOMConvertResponse struct {
	ScanResults       []*ScanResult        `json:"scanResults"`
	ConversionWarning []*ConversionWarning `json:"warnings"`
}
