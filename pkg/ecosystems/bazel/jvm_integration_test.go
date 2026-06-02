package bazel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/scatest"
)

// Only run when BAZEL_JVM_INTEGRATION_TESTS=1 (needs Bazel on PATH; Android fixture needs ANDROID_HOME / SDK).
func shouldSkipJVM(t *testing.T) {
	t.Helper()
	if os.Getenv("BAZEL_JVM_INTEGRATION_TESTS") != "1" {
		t.Skip("set BAZEL_JVM_INTEGRATION_TESTS=1 to run Bazel JVM integration tests")
	}
}

func TestPlugin_BuildDepGraphsFromDir_MatchJSON(t *testing.T) {
	shouldSkipJVM(t)

	fixtures := []string{
		"rules-jvm-external-6.10/spring_boot",
		"rules-jvm-external-7.0/spring_boot",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", fixture))
			require.NoError(t, err)

			opts := ecosystems.NewPluginOptions().WithBazelJvm(true)
			plugin := Plugin{}
			results, err := scatest.Run(ctx, plugin, logger.Nop(), root, opts)
			require.NoError(t, err)

			snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, snapshotResults(results))
		})
	}
}

func TestPlugin_BuildDepGraphsFromDir_NoOption_EmptyResult(t *testing.T) {
	shouldSkipJVM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	opts := ecosystems.NewPluginOptions() // no bazel option used
	plugin := Plugin{}
	results, err := scatest.Run(ctx, plugin, logger.Nop(), "./", opts)

	require.NoError(t, err)
	require.Empty(t, results)
}

func TestPlugin_BuildDepGraphsFromDir_AndriodBinary_MatchJSON(t *testing.T) {
	shouldSkipJVM(t)

	fixture := "rules-jvm-external-7.0/android_kotlin_app"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", fixture))
	require.NoError(t, err)

	opts := ecosystems.NewPluginOptions().
		WithBazelJvm(true).
		WithBazelTargetQuery("kind('android_binary', //...)") // override the default

	plugin := Plugin{}
	results, err := scatest.Run(ctx, plugin, logger.Nop(), root, opts)
	require.NoError(t, err)

	snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, snapshotResults(results))
}

func TestPlugin_BuildDepGraphsFromDir_JavaExport_MatchJSON(t *testing.T) {
	shouldSkipJVM(t)

	fixture := "rules-jvm-external-7.0/java-export"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", fixture))
	require.NoError(t, err)

	opts := ecosystems.NewPluginOptions().
		WithBazelJvm(true).
		WithBazelTargetQuery("kind('java_library', //...)") // override the default

	plugin := Plugin{}
	results, err := scatest.Run(ctx, plugin, logger.Nop(), root, opts)
	require.NoError(t, err)

	snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, snapshotResults(results))
}

func TestPlugin_BuildDepGraphsFromDir_ScalaBinary_MatchJSON(t *testing.T) {
	shouldSkipJVM(t)

	fixture := "rules-jvm-external-7.0/scala_akka"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures", "bazel", fixture))
	require.NoError(t, err)

	opts := ecosystems.NewPluginOptions().
		WithBazelJvm(true).
		WithBazelTargetQuery("kind('scala_binary', //...)") // override the default

	plugin := Plugin{}
	results, err := scatest.Run(ctx, plugin, logger.Nop(), root, opts)
	require.NoError(t, err)

	snaps.WithConfig(snaps.Dir(root)).MatchJSON(t, snapshotResults(results))
}
