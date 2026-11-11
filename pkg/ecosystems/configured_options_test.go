package ecosystems

import (
	"path/filepath"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
)

func TestNewPluginOptionsFromConfig_nativeSelectors(t *testing.T) {
	cases := []struct {
		name       string
		raw        []string
		configured bool
		want       GradleOptions
	}{
		{name: "raw selectors survive absent config", raw: []string{
			"--configuration-matching=runtime.*", "--configuration-attributes=usage:java-runtime", "--sub-project=api",
			"--all-sub-projects", "--init-script=custom.gradle", "--gradle-skip-wrapper", "--gradle-normalize-deps",
			"--include-provenance", "--workspace-package=python-api", "--project-name=my-project", "--no-build-isolation",
		}, want: GradleOptions{
			ConfigurationMatching: "runtime.*", ConfigurationAttributes: "usage:java-runtime",
			SubProject: "api", AllSubProjects: true, InitScript: "custom.gradle", SkipWrapper: true, NormalizeDeps: true,
		}},
		{name: "config selectors override raw", configured: true, raw: []string{
			"--configuration-matching=raw", "--configuration-attributes=raw:value", "--gradle-sub-project=raw",
			"--all-sub-projects", "--init-script=raw.gradle", "--gradle-normalize-deps", "--include-provenance",
		}, want: GradleOptions{
			ConfigurationMatching: "compile.*", ConfigurationAttributes: "usage:java-api",
			SubProject: "service", InitScript: "configured.gradle",
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			cfg.Set(configuration.RAW_CMD_ARGS, tt.raw)
			if tt.configured {
				cfg.Set(workflow.FlagConfigurationMatching, "compile.*")
				cfg.Set(workflow.FlagConfigurationAttributes, "usage:java-api")
				cfg.Set(workflow.FlagGradleSubProject, "service")
				cfg.Set(workflow.FlagAllSubProjects, false)
				cfg.Set(workflow.FlagInitScript, "configured.gradle")
				cfg.Set(workflow.FlagGradleNormalizeDeps, false)
				cfg.Set(workflow.FlagIncludeProvenance, false)
			}

			opts, err := NewPluginOptionsFromConfig(cfg)

			require.NoError(t, err)
			assert.Equal(t, tt.want, opts.Gradle)
			assert.Equal(t, tt.raw, opts.Global.RawFlags)
			assert.Equal(t, !tt.configured, opts.Global.IncludeProvenance)
			if !tt.configured {
				require.NotNil(t, opts.Global.WorkspacePackage)
				assert.Equal(t, "python-api", *opts.Global.WorkspacePackage)
				require.NotNil(t, opts.Global.ProjectName)
				assert.Equal(t, "my-project", *opts.Global.ProjectName)
				assert.True(t, opts.Python.NoBuildIsolation)
			}
		})
	}
}

func TestNewPluginOptionsFromConfig_dotnetFlags(t *testing.T) {
	t.Run("defaults leave every .NET option unset", func(t *testing.T) {
		opts, err := NewPluginOptionsFromConfig(configuration.New())
		require.NoError(t, err)

		assert.Empty(t, opts.Dotnet.TargetFramework, "every declared framework is reported")
		assert.False(t, opts.Dotnet.AssetsProjectName, "the directory-derived name is kept")
		assert.Empty(t, opts.Dotnet.PackagesFolder, "the resolver derives the location")
	})

	t.Run("the .NET flags reach DotnetOptions", func(t *testing.T) {
		config := configuration.New()
		config.Set(workflow.FlagDotnetTargetFramework, "net8.0")
		config.Set(workflow.FlagNugetAssetsProjectName, true)

		opts, err := NewPluginOptionsFromConfig(config)
		require.NoError(t, err)

		assert.Equal(t, "net8.0", opts.Dotnet.TargetFramework)
		assert.True(t, opts.Dotnet.AssetsProjectName)
	})

	// A moniker is not a path, so unlike --packages-folder it must survive
	// verbatim — the resolver compares it against what each project declares.
	t.Run("a target framework is forwarded verbatim", func(t *testing.T) {
		config := configuration.New()
		config.Set(workflow.FlagDotnetTargetFramework, "net7.0-windows")

		opts, err := NewPluginOptionsFromConfig(config)
		require.NoError(t, err)
		assert.Equal(t, "net7.0-windows", opts.Dotnet.TargetFramework)
	})

	t.Run("a packages folder is made absolute", func(t *testing.T) {
		config := configuration.New()
		config.Set(workflow.FlagNugetPkgsFolder, "packages")

		abs, err := filepath.Abs("packages")
		require.NoError(t, err)

		opts, err := NewPluginOptionsFromConfig(config)
		require.NoError(t, err)
		assert.Equal(t, abs, opts.Dotnet.PackagesFolder)
	})
}

func TestNewPluginOptionsFromConfig_DetectionDepth(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		wantDepth int
		wantErr   bool
	}{
		{name: "parses a positive depth", flagValue: "3", wantDepth: 3},
		{name: "unset leaves the walk unlimited", flagValue: "", wantDepth: 0},
		{name: "trims surrounding whitespace", flagValue: " 3 ", wantDepth: 3},
		// snyk/cli rejects each of these, so we do too.
		{name: "rejects zero", flagValue: "0", wantErr: true},
		{name: "rejects a negative depth", flagValue: "-2", wantErr: true},
		{name: "rejects a non-numeric value", flagValue: "abc", wantErr: true},
		// Deliberate divergence: snyk/cli's Number() coercion accepts this.
		{name: "rejects a fractional depth", flagValue: "3.5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.New()
			config.Set(workflow.FlagDetectionDepth, tt.flagValue)

			opts, err := NewPluginOptionsFromConfig(config)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, opts)

				var snykErr snyk_errors.Error
				require.ErrorAs(t, err, &snykErr)
				assert.Contains(t, snykErr.Detail, "Expected a positive integer")
				assert.Contains(t, snykErr.Detail, tt.flagValue)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantDepth, opts.Global.DetectionDepth)
		})
	}
}

func Test_parseExcludeFlag(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:     "single value",
			input:    "dir1",
			expected: []string{"dir1"},
		},
		{
			name:     "multiple values",
			input:    "dir1,dir2,dir3",
			expected: []string{"dir1", "dir2", "dir3"},
		},
		{
			name:     "trims whitespace around values",
			input:    "dir1, dir2 , dir3",
			expected: []string{"dir1", "dir2", "dir3"},
		},
		{
			name:     "filters empty entries",
			input:    "dir1,,dir2,",
			expected: []string{"dir1", "dir2"},
		},
		{
			name:     "only commas returns nil",
			input:    ",,,",
			expected: nil,
		},
		{
			name:     "whitespace only entries are filtered",
			input:    "dir1,   ,dir2",
			expected: []string{"dir1", "dir2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseExcludeFlag(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
