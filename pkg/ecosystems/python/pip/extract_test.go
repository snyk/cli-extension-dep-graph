package pip

import (
	"testing"
)

func TestExtractFailedPackageName(t *testing.T) {
	tests := map[string]struct {
		stderr   string
		expected string
	}{
		"metadata_generation_failed_simple": {
			stderr: `error: metadata-generation-failed

× Encountered error while generating package metadata.
╰─> gensim

note: This is an issue with the package mentioned above, not pip.`,
			expected: "gensim",
		},
		"metadata_generation_failed_with_lines_of_output": {
			stderr: `error: subprocess-exited-with-error
  
  × Preparing metadata (pyproject.toml) did not run successfully.
  │ exit code: 1
  ╰─> [10 lines of output]
      + meson setup /tmp/pip-install-18e5wn4x/pandas_363f78496e4d425bbbcaca33978fbd75
      Build type: native build
      
      ../meson.build:5:13: ERROR: Command failed with status 1.
      [end of output]
  
  note: This error originates from a subprocess, and is likely not a problem with pip.
error: metadata-generation-failed

× Encountered error while generating package metadata.
╰─> pandas

note: This is an issue with the package mentioned above, not pip.`,
			expected: "pandas",
		},
		"failed_to_build_wheel": {
			stderr:   `ERROR: Failed to build 'gensim' when getting requirements to build wheel`,
			expected: "gensim",
		},
		"failed_building_wheel_for": {
			stderr:   `ERROR: Failed building wheel for numpy`,
			expected: "numpy",
		},
		"could_not_build_wheels": {
			stderr:   `ERROR: Could not build wheels for scipy which is required`,
			expected: "scipy",
		},
		"no_match": {
			stderr:   `Some random error message`,
			expected: "",
		},
		"lines_of_output_only": {
			stderr: `╰─> [34 lines of output]
      Some error details
      [end of output]`,
			expected: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := extractFailedPackageName(tt.stderr)
			if result != tt.expected {
				t.Errorf("extractFailedPackageName() = %q, want %q", result, tt.expected)
			}
		})
	}
}
