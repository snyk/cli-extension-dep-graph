//go:build integration && gradle

package gradle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// deepChainModuleCount is deliberately above the depth at which the recursive
// walker this replaced ran out of thread stack (CMPA-770): it resolved fine at
// ~250 modules and died at ~350+, so a shallower fixture would pass either way.
const deepChainModuleCount = 400

// TestPlugin_DeepDependencyChain resolves a chain of project dependencies deep
// enough to overflow the daemon's default thread stack under a recursive walk.
// The fixture is generated rather than committed — 400 module directories is
// not something to carry in testdata — and declares no repositories, so the
// test exercises the walker and not the network.
func TestPlugin_DeepDependencyChain(t *testing.T) {
	projectDir := t.TempDir()
	writeDeepChain(t, projectDir, deepChainModuleCount)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	plugin := NewGradlePlugin()
	results, err := scatest.Run(ctx, plugin, logger.Nop(), projectDir, ecosystems.NewPluginOptions())
	require.NoError(t, err, "deep chain should resolve without exhausting the JVM thread stack")
	require.NotEmpty(t, results, "plugin must emit at least one result")

	// A walker that "passes" by resolving nothing is not a pass. The head of
	// the chain reaches every module below it, so the deepest graph produced
	// has to hold the head plus all of them.
	deepest := 0
	for _, result := range results {
		if result.DepGraph == nil {
			continue
		}
		if n := len(result.DepGraph.Pkgs); n > deepest {
			deepest = n
		}
	}
	require.Equal(t, deepChainModuleCount, deepest,
		"deepest graph should hold the head of the chain plus every module below it")
}

// writeDeepChain generates a Gradle build of moduleCount projects where each
// depends on the next, i.e. a single chain of depth moduleCount.
func writeDeepChain(t *testing.T, root string, moduleCount int) {
	t.Helper()

	var settings strings.Builder
	settings.WriteString("rootProject.name = 'deep-chain'\n")
	for i := 0; i < moduleCount; i++ {
		fmt.Fprintf(&settings, "include 'm%d'\n", i)
	}
	writeFile(t, filepath.Join(root, "settings.gradle"), settings.String())
	writeFile(t, filepath.Join(root, "build.gradle"), "allprojects { apply plugin: 'java-library' }\n")

	for i := 0; i < moduleCount; i++ {
		dir := filepath.Join(root, fmt.Sprintf("m%d", i))
		src := filepath.Join(dir, "src", "main", "java")
		require.NoError(t, os.MkdirAll(src, 0o755))

		dep := ""
		if i+1 < moduleCount {
			dep = fmt.Sprintf("    api project(':m%d')\n", i+1)
		}
		writeFile(t, filepath.Join(dir, "build.gradle"), fmt.Sprintf("dependencies {\n%s}\n", dep))
		writeFile(t, filepath.Join(src, fmt.Sprintf("C%d.java", i)), fmt.Sprintf("public class C%d {}\n", i))
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}
