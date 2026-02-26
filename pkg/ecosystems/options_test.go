package ecosystems

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPluginOptionsFromRawFlags_AllFields(t *testing.T) {
	targetFile := "requirements.txt"

	tests := []struct {
		name     string
		rawFlags []string
		expected *SCAPluginOptions
		wantErr  bool
	}{
		{
			name: "all fields set",
			rawFlags: []string{
				"--target-file", targetFile,
				"--all-projects",
				"--dev",
				"--exclude", "foo",
				"--no-build-isolation",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  &targetFile,
					AllProjects: true,
					IncludeDev:  true,
					Exclude:     []string{"foo"},
				},
				Python: PythonOptions{
					NoBuildIsolation: true,
				},
			},
			wantErr: false,
		},
		{
			name:     "no arguments",
			rawFlags: []string{},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  nil,
					AllProjects: false,
					IncludeDev:  false,
				},
				Python: PythonOptions{
					NoBuildIsolation: false,
				},
			},
			wantErr: false,
		},
		{
			name: "only target file",
			rawFlags: []string{
				"--target-file", targetFile,
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  &targetFile,
					AllProjects: false,
					IncludeDev:  false,
				},
				Python: PythonOptions{
					NoBuildIsolation: false,
				},
			},
			wantErr: false,
		},
		{
			name: "only all-projects",
			rawFlags: []string{
				"--all-projects",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  nil,
					AllProjects: true,
					IncludeDev:  false,
				},
				Python: PythonOptions{
					NoBuildIsolation: false,
				},
			},
			wantErr: false,
		},
		{
			name: "only dev",
			rawFlags: []string{
				"--dev",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  nil,
					AllProjects: false,
					IncludeDev:  true,
				},
				Python: PythonOptions{
					NoBuildIsolation: false,
				},
			},
			wantErr: false,
		},
		{
			name: "only d",
			rawFlags: []string{
				"-d",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  nil,
					AllProjects: false,
					IncludeDev:  true,
				},
				Python: PythonOptions{
					NoBuildIsolation: false,
				},
			},
			wantErr: false,
		},
		{
			name: "only exclude",
			rawFlags: []string{
				"--exclude", "foo,bar",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					Exclude: []string{"foo", "bar"},
				},
			},
			wantErr: false,
		},
		{
			name: "only no-build-isolation",
			rawFlags: []string{
				"--no-build-isolation",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  nil,
					AllProjects: false,
					IncludeDev:  false,
				},
				Python: PythonOptions{
					NoBuildIsolation: true,
				},
			},
			wantErr: false,
		},
		{
			name: "mixed boolean flags",
			rawFlags: []string{
				"--all-projects",
				"--no-build-isolation",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:  nil,
					AllProjects: true,
					IncludeDev:  false,
				},
				Python: PythonOptions{
					NoBuildIsolation: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPluginOptionsFromRawFlags(tt.rawFlags)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			tt.expected.Global.RawFlags = tt.rawFlags
			assert.Equal(t, tt.expected, got)
		})
	}
}
