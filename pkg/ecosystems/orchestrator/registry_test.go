package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/orchestrator/registry"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pipenv"
)

// TestNoPluginConflicts validates that all registered plugins have unique capability definitions.
// This test ensures that no two plugins can handle the same set of files (primary manifest + required companions).
// This test runs in the orchestrator package where plugins are registered via init().
func TestNoPluginConflicts(t *testing.T) {
	reg := registry.NewRegistry()

	require.NoError(t, reg.RegisterPlugin(&pip.Plugin{}))
	require.NoError(t, reg.RegisterPlugin(&pipenv.Plugin{}))

	plugins := reg.AllPlugins()

	if len(plugins) == 0 {
		t.Fatal("no plugins registered in global registry")
	}

	t.Logf("Testing %d registered plugins for conflicts", len(plugins))

	// Check all pairs of plugins for conflicts
	for i, p1 := range plugins {
		for j, p2 := range plugins {
			if i >= j {
				continue // Skip same plugin and already checked pairs
			}

			conflict := detectConflict(
				p1.Capability(),
				p2.Capability(),
			)

			if conflict != nil {
				t.Errorf("Plugin conflict detected between %s and %s: %v",
					p1.Name(),
					p2.Name(),
					conflict)
			}
		}
	}
}

// detectConflict checks if two plugin capabilities conflict.
// Two plugins conflict if they have identical file requirements (same primary manifest + same required companions).
func detectConflict(cap1, cap2 ecosystems.PluginCapability) error {
	// For each primary manifest in cap1
	for _, primary1 := range cap1.PrimaryManifests {
		for _, primary2 := range cap2.PrimaryManifests {
			if primary1 == primary2 {
				// Same primary manifest - check if companions are identical
				if setsEqual(cap1.RequiredCompanions, cap2.RequiredCompanions) {
					return &ConflictError{
						Primary:    primary1,
						Companions: cap1.RequiredCompanions,
					}
				}
			}
		}
	}
	return nil
}

// setsEqual checks if two string slices contain the same elements (order-independent).
func setsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create a map for quick lookup
	aMap := make(map[string]bool)
	for _, item := range a {
		aMap[item] = true
	}

	// Check if all items in b exist in a
	for _, item := range b {
		if !aMap[item] {
			return false
		}
	}

	return true
}

// ConflictError represents a plugin conflict.
type ConflictError struct {
	Primary    string
	Companions []string
}

func (e *ConflictError) Error() string {
	if len(e.Companions) == 0 {
		return "both plugins handle '" + e.Primary + "' with no required companions"
	}
	return "both plugins handle '" + e.Primary + "' with same required companions"
}

// TestRegisteredPlugins verifies that expected plugins are registered.
func TestRegisteredPlugins(t *testing.T) {
	reg := registry.NewRegistry()

	require.NoError(t, reg.RegisterPlugin(&pip.Plugin{}))
	require.NoError(t, reg.RegisterPlugin(&pipenv.Plugin{}))

	plugins := reg.AllPlugins()

	// Expected plugins
	expectedPlugins := map[string]bool{
		"pip":    false,
		"pipenv": false,
	}

	// Check which plugins are registered
	for _, plugin := range plugins {
		name := plugin.Name()
		if _, expected := expectedPlugins[name]; expected {
			expectedPlugins[name] = true
		}
	}

	// Verify all expected plugins are present
	for name, found := range expectedPlugins {
		if !found {
			t.Errorf("expected plugin %s not found in registry", name)
		}
	}

	t.Logf("Successfully verified %d registered plugins", len(expectedPlugins))
}
