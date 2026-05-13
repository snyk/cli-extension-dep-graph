//go:build !integration

package gradle

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOptions(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("accepts nil options", func(t *testing.T) {
		err := ValidateOptions(tempDir, nil)
		require.NoError(t, err)
	})

	t.Run("accepts empty options", func(t *testing.T) {
		options := &ecosystems.SCAPluginOptions{}
		err := ValidateOptions(tempDir, options)
		require.NoError(t, err)
	})

	t.Run("accepts valid configuration matching regex", func(t *testing.T) {
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "(?i).*runtime.*"
		err := ValidateOptions(tempDir, options)
		require.NoError(t, err)
	})

	t.Run("accepts empty configuration matching string", func(t *testing.T) {
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = ""
		err := ValidateOptions(tempDir, options)
		require.NoError(t, err)
	})

	t.Run("rejects invalid configuration matching regex", func(t *testing.T) {
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "[invalid-regex"
		err := ValidateOptions(tempDir, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid --configuration-matching regex pattern")
		assert.Contains(t, err.Error(), "[invalid-regex")
	})

	t.Run("validates complex regex patterns", func(t *testing.T) {
		testCases := []struct {
			name    string
			pattern string
			valid   bool
		}{
			{"exact match", "^runtimeClasspath$", true},
			{"case insensitive", "(?i).*runtime.*", true},
			{"alternation", "(compile|runtime)Classpath", true},
			{"word boundaries", "\\bcompile\\b", true},
			{"unclosed bracket", "[invalid", false},
			{"unclosed paren", "(unclosed", false},
			{"invalid escape", "\\k", false},
			{"empty pattern is valid", "", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				options := &ecosystems.SCAPluginOptions{}
				options.Gradle.ConfigurationMatching = tc.pattern
				err := ValidateOptions(tempDir, options)
				if tc.valid {
					require.NoError(t, err, "pattern %q should be valid", tc.pattern)
				} else {
					require.Error(t, err, "pattern %q should be invalid", tc.pattern)
					assert.Contains(t, err.Error(), "invalid --configuration-matching regex pattern")
				}
			})
		}
	})

	t.Run("accepts valid configuration attributes", func(t *testing.T) {
		testCases := []string{
			"buildtype:release",
			"usage:java-runtime",
			"buildtype:release,usage:java-runtime",
			"buildType:debug,usage:java-api,category:library",
			"BUILDTYPE:DEBUG", // case doesn't matter in values
		}

		for _, attrs := range testCases {
			t.Run(attrs, func(t *testing.T) {
				options := &ecosystems.SCAPluginOptions{}
				options.Gradle.ConfigurationAttributes = attrs
				err := ValidateOptions(tempDir, options)
				require.NoError(t, err, "attributes %q should be valid", attrs)
			})
		}
	})

	t.Run("accepts empty configuration attributes string", func(t *testing.T) {
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationAttributes = ""
		err := ValidateOptions(tempDir, options)
		require.NoError(t, err)
	})

	t.Run("rejects invalid configuration attributes", func(t *testing.T) {
		testCases := []struct {
			name   string
			attrs  string
			errMsg string
		}{
			{"missing value", "buildtype:", "has empty value"},
			{"missing key", ":release", "has empty key"},
			{"no colon", "buildtype", "must be in 'key:value' format"},
			{"multiple colons", "build:type:release", "must be in 'key:value' format"},
			{"empty entry in list", "buildtype:release,,usage:java-runtime", "entry 2 is empty"},
			{"whitespace only", "   ", "cannot be empty"},
			{"missing key with whitespace", "  :release", "has empty key"},
			{"missing value with whitespace", "buildtype:  ", "has empty value"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				options := &ecosystems.SCAPluginOptions{}
				options.Gradle.ConfigurationAttributes = tc.attrs
				err := ValidateOptions(tempDir, options)
				require.Error(t, err, "attributes %q should be invalid", tc.attrs)
				assert.Contains(t, err.Error(), "--configuration-attributes")
				assert.Contains(t, err.Error(), tc.errMsg)
			})
		}
	})

	t.Run("validates absolute init script paths", func(t *testing.T) {
		dir := t.TempDir()

		// Test with existing file
		validScript := filepath.Join(dir, "valid.gradle")
		require.NoError(t, os.WriteFile(validScript, []byte("// valid script"), 0o644))

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.InitScript = validScript
		err := ValidateOptions(dir, options)
		require.NoError(t, err)

		// Test with non-existent file
		options.Gradle.InitScript = filepath.Join(dir, "nonexistent.gradle")
		err = ValidateOptions(dir, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script not found")

		// Test with directory instead of file
		scriptDir := filepath.Join(dir, "scriptdir")
		require.NoError(t, os.Mkdir(scriptDir, 0o755))
		options.Gradle.InitScript = scriptDir
		err = ValidateOptions(dir, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script is a directory")
	})

	t.Run("validates relative init script paths", func(t *testing.T) {
		dir := t.TempDir()

		// Create a valid relative script
		scriptsDir := filepath.Join(dir, "scripts")
		require.NoError(t, os.MkdirAll(scriptsDir, 0o755))
		validScript := filepath.Join(scriptsDir, "custom.gradle")
		require.NoError(t, os.WriteFile(validScript, []byte("// custom script"), 0o644))

		// Test with valid relative path
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.InitScript = "scripts/custom.gradle"
		err := ValidateOptions(dir, options)
		require.NoError(t, err)

		// Test with non-existent relative path
		options.Gradle.InitScript = "scripts/nonexistent.gradle"
		err = ValidateOptions(dir, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script not found")

		// Test with empty path
		options.Gradle.InitScript = "   "
		err = ValidateOptions(dir, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script path is empty")

		// Test with relative path that is a directory
		options.Gradle.InitScript = "scripts"
		err = ValidateOptions(dir, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user init script is a directory")

		// Test that file extension doesn't matter
		customScript := filepath.Join(scriptsDir, "custom-init.txt")
		require.NoError(t, os.WriteFile(customScript, []byte("// custom init"), 0o644))
		options.Gradle.InitScript = "scripts/custom-init.txt"
		err = ValidateOptions(dir, options)
		require.NoError(t, err)
	})
}

// Integration test to ensure BuildDepGraphsFromDir fails fast with invalid options
func TestValidateOptions_Integration_BuildDepGraphsFromDir(t *testing.T) {
	t.Run("BuildDepGraphsFromDir fails fast with invalid regex", func(t *testing.T) {
		dir := t.TempDir()
		buildFile := filepath.Join(dir, "build.gradle")
		require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "[invalid-regex"

		ctx := context.Background()
		log := logger.Nop()
		plugin := Plugin{}

		// This should fail fast during validation, before any file discovery or Gradle execution
		result, err := plugin.BuildDepGraphsFromDir(ctx, log, dir, options)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "gradle: invalid options:")
		assert.Contains(t, err.Error(), "invalid --configuration-matching regex pattern")
		assert.Contains(t, err.Error(), "[invalid-regex")
	})

	t.Run("BuildDepGraphsFromDir fails fast with invalid init script", func(t *testing.T) {
		dir := t.TempDir()
		buildFile := filepath.Join(dir, "build.gradle")
		require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.InitScript = "/nonexistent/init.gradle"

		ctx := context.Background()
		log := logger.Nop()
		plugin := Plugin{}

		// This should fail fast during validation, before any file discovery
		result, err := plugin.BuildDepGraphsFromDir(ctx, log, dir, options)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "gradle: invalid options:")
		assert.Contains(t, err.Error(), "user init script not found")
	})

	t.Run("BuildDepGraphsFromDir fails fast with invalid configuration attributes", func(t *testing.T) {
		dir := t.TempDir()
		buildFile := filepath.Join(dir, "build.gradle")
		require.NoError(t, os.WriteFile(buildFile, []byte(""), 0o644))

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationAttributes = "buildtype:" // missing value

		ctx := context.Background()
		log := logger.Nop()
		plugin := Plugin{}

		// This should fail fast during validation, before any file discovery or Gradle execution
		result, err := plugin.BuildDepGraphsFromDir(ctx, log, dir, options)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "gradle: invalid options:")
		assert.Contains(t, err.Error(), "--configuration-attributes")
		assert.Contains(t, err.Error(), "has empty value")
	})
}
