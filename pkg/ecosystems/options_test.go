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
				"--fail-fast",
				"--strict-out-of-sync", "false",
				"--force-single-graph",
				"--internal-uv-workspace-packages",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					TargetFile:                    &targetFile,
					AllProjects:                   true,
					IncludeDev:                    true,
					Exclude:                       []string{"foo"},
					FailFast:                      true,
					AllowOutOfSync:                true,
					ForceSingleGraph:              true,
					ForceIncludeWorkspacePackages: true,
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
			name: "only exclude with single value",
			rawFlags: []string{
				"--exclude=Pipfile",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					Exclude: []string{"Pipfile"},
				},
			},
			wantErr: false,
		},
		{
			name: "exclude with multiple comma-separated values using equals syntax",
			rawFlags: []string{
				"--exclude=test1,test2,test3",
			},
			expected: &SCAPluginOptions{
				Global: GlobalOptions{
					Exclude: []string{"test1", "test2", "test3"},
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

func TestNewPluginOptionsFromRawFlags_FailFast(t *testing.T) {
	got, err := NewPluginOptionsFromRawFlags([]string{"--fail-fast"})

	assert.NoError(t, err)
	assert.True(t, got.Global.FailFast)
}

func TestNewPluginOptionsFromRawFlags_ForceSingleGraph(t *testing.T) {
	got, err := NewPluginOptionsFromRawFlags([]string{"--force-single-graph"})

	assert.NoError(t, err)
	assert.True(t, got.Global.ForceSingleGraph)
}

func TestNewPluginOptionsFromRawFlags_ForceIncludeWorkspacePackages(t *testing.T) {
	got, err := NewPluginOptionsFromRawFlags([]string{"--internal-uv-workspace-packages"})

	assert.NoError(t, err)
	assert.True(t, got.Global.ForceIncludeWorkspacePackages)
}

func TestNewPluginOptionsFromRawFlags_StrictOutOfSync(t *testing.T) {
	tests := []struct {
		name                   string
		rawFlags               []string
		expectedAllowOutOfSync bool
	}{
		{
			name:                   "strict-out-of-sync=false sets AllowOutOfSync to true",
			rawFlags:               []string{"--strict-out-of-sync", "false"},
			expectedAllowOutOfSync: true,
		},
		{
			name:                   "strict-out-of-sync=true sets AllowOutOfSync to false",
			rawFlags:               []string{"--strict-out-of-sync", "true"},
			expectedAllowOutOfSync: false,
		},
		{
			name:                   "absent strict-out-of-sync defaults AllowOutOfSync to false",
			rawFlags:               []string{},
			expectedAllowOutOfSync: false,
		},
		{
			name:                   "invalid strict-out-of-sync defaults AllowOutOfSync to false",
			rawFlags:               []string{"--strict-out-of-sync", "invalid"},
			expectedAllowOutOfSync: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPluginOptionsFromRawFlags(tt.rawFlags)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedAllowOutOfSync, got.Global.AllowOutOfSync)
		})
	}
}

func TestNewPluginOptionsFromRawFlags_UnknownFlags(t *testing.T) {
	rawFlags := []string{
		"--unknown-flag", "value",
		"--target-file", "package.json",
		"--dev",
		"--another-unknown",
	}

	got, err := NewPluginOptionsFromRawFlags(rawFlags)
	assert.NoError(t, err)
	assert.NotNil(t, got.Global.TargetFile)
	assert.Equal(t, "package.json", *got.Global.TargetFile)
	assert.True(t, got.Global.IncludeDev)
}
