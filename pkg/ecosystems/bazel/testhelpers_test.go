package bazel

import (
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

// snapshotResults wraps results in the shape JSON snapshot tests
// compare against. ProcessedFiles is asserted by tests that care
// (assertGoProcessedFiles, etc.); the snapshot keeps an empty list
// so host-specific paths don't leak into the golden file.
func snapshotResults(results []ecosystems.SCAResult) any {
	cleaned := make([]ecosystems.SCAResult, len(results))
	copy(cleaned, results)
	for i := range cleaned {
		cleaned[i].ProcessedFiles = nil
	}
	return struct {
		Results        []ecosystems.SCAResult `json:"results"`
		ProcessedFiles []string               `json:"processedFiles"`
	}{
		Results:        cleaned,
		ProcessedFiles: []string{},
	}
}
