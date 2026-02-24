package registry

import (
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// TestRegistryOperations tests basic registry operations.
func TestRegistryOperations(t *testing.T) {
	// Create a new registry for testing
	reg := NewRegistry()

	// Test registering a plugin
	mockPlug := &mockPlugin{
		name: "test-plugin",
		capability: ecosystems.PluginCapability{
			PrimaryManifests:   []string{"test.txt"},
			RequiredCompanions: []string{},
		},
	}

	err := reg.RegisterPlugin(mockPlug)
	if err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	// Test getting the plugin
	plugin, exists := reg.Get("test-plugin")
	if !exists {
		t.Error("expected plugin to exist")
	}
	if plugin.Name() != "test-plugin" {
		t.Errorf("expected plugin name 'test-plugin', got %s", plugin.Name())
	}

	// Test duplicate registration
	err = reg.RegisterPlugin(mockPlug)
	if err == nil {
		t.Error("expected error when registering duplicate plugin")
	}

	// Test getting non-existent plugin
	_, exists = reg.Get("non-existent")
	if exists {
		t.Error("expected plugin to not exist")
	}

	// Test AllPlugins
	allPlugins := reg.AllPlugins()
	if len(allPlugins) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(allPlugins))
	}
}
