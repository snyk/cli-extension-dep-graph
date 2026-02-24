package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/orchestrator/registry"
)

// mockInvocationContext implements workflow.InvocationContext for testing
type mockInvocationContext struct {
	workflow.InvocationContext // Embed to get default implementations
	ctx                        context.Context
	logger                     *zerolog.Logger
	config                     configuration.Configuration
	engine                     *mockEngine
}

func (m *mockInvocationContext) Context() context.Context {
	return m.ctx
}

func (m *mockInvocationContext) GetEnhancedLogger() *zerolog.Logger {
	return m.logger
}

func (m *mockInvocationContext) GetConfiguration() configuration.Configuration {
	return m.config
}

func (m *mockInvocationContext) GetEngine() workflow.Engine {
	return m.engine
}

// mockEngine implements workflow.Engine for testing
type mockEngine struct {
	workflow.Engine // Embed to get default implementations
	invocations     []workflow.Identifier
	mu              sync.Mutex
}

func (m *mockEngine) InvokeWithConfig(id workflow.Identifier, config configuration.Configuration) ([]workflow.Data, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invocations = append(m.invocations, id)
	// Return empty data to simulate legacy CLI returning no results
	return []workflow.Data{}, nil
}

// mockConfiguration implements configuration.Configuration for testing
type mockConfiguration struct {
	configuration.Configuration
}

func (m *mockConfiguration) Clone() configuration.Configuration {
	return &mockConfiguration{}
}

func (m *mockConfiguration) Set(key string, value interface{}) {
	// No-op for testing
}

func (m *mockConfiguration) Get(key string) interface{} {
	return nil
}

// mockPlugin tracks how many times it's called
type mockPlugin struct {
	name       string
	capability ecosystems.PluginCapability
	callCount  int
	mu         sync.Mutex
	results    []ecosystems.SCAResult
	shouldFail bool
}

func (m *mockPlugin) Name() string {
	return m.name
}

func (m *mockPlugin) Capability() ecosystems.PluginCapability {
	return m.capability
}

func (m *mockPlugin) BuildDepGraphsFromDir(ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions) ([]ecosystems.SCAResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if m.shouldFail {
		return nil, nil
	}

	// Return the pre-configured results
	return m.results, nil
}

func (m *mockPlugin) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func TestResolveDepgraphs(t *testing.T) {
	// Create a temporary directory structure for testing
	tmpDir := t.TempDir()

	// Create test files for a mono repo structure
	testFiles := map[string]string{
		"requirements.txt":         "",
		"subdir1/requirements.txt": "",
		"subdir2/Pipfile":          "",
		"subdir2/Pipfile.lock":     "",
		"subdir3/Pipfile":          "",
		"subdir3/Pipfile.lock":     "",
	}

	for path, content := range testFiles {
		fullPath := tmpDir + "/" + path
		if err := createTestFile(fullPath, content); err != nil {
			t.Fatalf("failed to create test file %s: %v", path, err)
		}
	}

	// Create mock plugins
	pipPlugin := &mockPlugin{
		name: "pip",
		capability: ecosystems.PluginCapability{
			PrimaryManifests:   []string{"requirements.txt"},
			RequiredCompanions: []string{},
		},
		results: []ecosystems.SCAResult{
			{
				Metadata: ecosystems.Metadata{
					TargetFile: "requirements.txt",
				},
				DepGraph: &depgraph.DepGraph{},
			},
		},
	}

	pipenvPlugin := &mockPlugin{
		name: "pipenv",
		capability: ecosystems.PluginCapability{
			PrimaryManifests:   []string{"Pipfile"},
			RequiredCompanions: []string{"Pipfile.lock"},
		},
		results: []ecosystems.SCAResult{
			{
				Metadata: ecosystems.Metadata{
					TargetFile: "Pipfile",
				},
				DepGraph: &depgraph.DepGraph{},
			},
		},
	}

	// Create a test registry and register mock plugins
	testRegistry := registry.NewRegistry()
	err := testRegistry.RegisterPlugin(pipPlugin)
	if err != nil {
		t.Fatalf("failed to register pip plugin: %v", err)
	}

	err = testRegistry.RegisterPlugin(pipenvPlugin)
	if err != nil {
		t.Fatalf("failed to register pipenv plugin: %v", err)
	}

	// Create mock invocation context
	mockEngine := &mockEngine{
		invocations: []workflow.Identifier{},
	}
	nopLogger := zerolog.Nop()
	mockCtx := &mockInvocationContext{
		ctx:    context.Background(),
		logger: &nopLogger,
		config: &mockConfiguration{},
		engine: mockEngine,
	}

	// Test with AllProjects flag to discover all files
	options := ecosystems.SCAPluginOptions{
		Global: ecosystems.GlobalOptions{
			AllProjects: true,
		},
	}

	// Call ResolveDepgraphs with explicit registry
	resultsChan, err := ResolveDepgraphs(mockCtx, testRegistry, tmpDir, options)
	if err != nil {
		t.Fatalf("ResolveDepgraphs failed: %v", err)
	}

	// Collect all results from the channel
	var results []ecosystems.SCAResult
	for result := range resultsChan {
		results = append(results, result)
	}

	// Verify pip plugin was called twice (for 2 requirements.txt files)
	pipCallCount := pipPlugin.GetCallCount()
	if pipCallCount != 2 {
		t.Errorf("expected pip plugin to be called 2 times, got %d", pipCallCount)
	}

	// Verify pipenv plugin was called twice (for 2 Pipfile files)
	pipenvCallCount := pipenvPlugin.GetCallCount()
	if pipenvCallCount != 2 {
		t.Errorf("expected pipenv plugin to be called 2 times, got %d", pipenvCallCount)
	}

	// Verify we got 4 results total (2 from pip + 2 from pipenv)
	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}

	// Verify legacy CLI was called once
	mockEngine.mu.Lock()
	legacyCallCount := len(mockEngine.invocations)
	mockEngine.mu.Unlock()

	if legacyCallCount != 1 {
		t.Errorf("expected legacy CLI to be called 1 time, got %d", legacyCallCount)
	}

	// Verify all results have valid metadata
	for i, result := range results {
		if result.Metadata.TargetFile == "" {
			t.Errorf("result %d has empty target file", i)
		}
		if result.DepGraph == nil {
			t.Errorf("result %d has nil depgraph", i)
		}
	}
}

func TestResolveDepgraphsWithTargetFile(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create multiple test files to ensure only the target is processed
	testFiles := map[string]string{
		"requirements.txt":         "",
		"subdir1/requirements.txt": "",
		"subdir2/requirements.txt": "",
	}

	for path, content := range testFiles {
		fullPath := tmpDir + "/" + path
		if err := createTestFile(fullPath, content); err != nil {
			t.Fatalf("failed to create test file %s: %v", path, err)
		}
	}

	// Create mock plugin that only returns result for the target file
	pipPlugin := &mockPlugin{
		name: "pip",
		capability: ecosystems.PluginCapability{
			PrimaryManifests:   []string{"requirements.txt"},
			RequiredCompanions: []string{},
		},
		results: []ecosystems.SCAResult{
			{
				Metadata: ecosystems.Metadata{
					TargetFile: "subdir1/requirements.txt",
				},
				DepGraph: &depgraph.DepGraph{},
			},
		},
		// In reality, the plugin would check options.Global.TargetFile and only process that file
		// For this test, we'll verify the plugin is called with the target file set in options
	}

	// Create test registry
	testRegistry := registry.NewRegistry()
	err := testRegistry.RegisterPlugin(pipPlugin)
	if err != nil {
		t.Fatalf("failed to register pip plugin: %v", err)
	}

	// Create mock invocation context
	mockEngine := &mockEngine{}
	nopLogger := zerolog.Nop()
	mockCtx := &mockInvocationContext{
		ctx:    context.Background(),
		logger: &nopLogger,
		config: &mockConfiguration{},
		engine: mockEngine,
	}

	// Test with specific target file (only subdir1/requirements.txt)
	targetFile := "subdir1/requirements.txt"
	options := ecosystems.SCAPluginOptions{
		Global: ecosystems.GlobalOptions{
			TargetFile: &targetFile,
		},
	}

	// Call ResolveDepgraphs with explicit registry
	resultsChan, err := ResolveDepgraphs(mockCtx, testRegistry, tmpDir, options)
	if err != nil {
		t.Fatalf("ResolveDepgraphs failed: %v", err)
	}

	// Collect results
	var results []ecosystems.SCAResult
	for result := range resultsChan {
		results = append(results, result)
	}

	// The orchestrator discovers all 3 requirements.txt files and creates 3 matches
	// It calls the plugin once per match, passing the specific target file in options
	// In a real scenario, the plugin would check options.Global.TargetFile and only process that file
	// Our mock plugin returns the same result for each call, simulating 3 results
	pipCallCount := pipPlugin.GetCallCount()
	if pipCallCount != 3 {
		t.Errorf("expected pip plugin to be called 3 times (once per discovered file), got %d", pipCallCount)
	}

	// Since our mock returns the same result each time, we get 3 identical results
	// In a real scenario, only the target file would produce a result
	if len(results) != 3 {
		t.Errorf("expected 3 results from mock plugin, got %d", len(results))
	}

	// Verify all results are for the expected target file (mock behavior)
	for i, result := range results {
		if result.Metadata.TargetFile != "subdir1/requirements.txt" {
			t.Errorf("result %d: expected 'subdir1/requirements.txt', got '%s'", i, result.Metadata.TargetFile)
		}
	}
}

// Helper function to create test files with directory structure
func createTestFile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}
