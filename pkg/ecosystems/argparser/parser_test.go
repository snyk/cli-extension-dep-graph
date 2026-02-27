package argparser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test struct with various data types.
type TestOptions struct {
	// Boolean flags
	BoolFlag   bool `arg:"--bool-flag"`
	ShortFlag  bool `arg:"-b"`
	MultiAlias bool `arg:"--multi,--m,-x"`

	// String flags
	StringFlag string  `arg:"--string"`
	StringPtr  *string `arg:"--string-ptr"`

	// Slice flags
	SliceFlag []string `arg:"--slice"`

	// Custom type with UnmarshalText
	CustomFlag CommaSeparated `arg:"--custom"`
}

// CommaSeparated is a test type that implements UnmarshalText.
type CommaSeparated []string

func (c *CommaSeparated) UnmarshalText(text []byte) error {
	*c = strings.Split(string(text), ",")
	return nil
}

func TestParse_BooleanFlags(t *testing.T) {
	tests := []struct {
		name     string
		rawFlags []string
		check    func(*testing.T, *TestOptions)
	}{
		{
			name:     "single boolean flag",
			rawFlags: []string{"--bool-flag"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.BoolFlag)
			},
		},
		{
			name:     "short flag",
			rawFlags: []string{"-b"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.ShortFlag)
			},
		},
		{
			name:     "multi-alias flag - first alias",
			rawFlags: []string{"--multi"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.MultiAlias)
			},
		},
		{
			name:     "multi-alias flag - second alias",
			rawFlags: []string{"--m"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.MultiAlias)
			},
		},
		{
			name:     "multi-alias flag - short alias",
			rawFlags: []string{"-x"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.MultiAlias)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &TestOptions{}
			err := Parse(tt.rawFlags, opts)
			assert.NoError(t, err)
			tt.check(t, opts)
		})
	}
}

func TestParse_StringFlags(t *testing.T) {
	tests := []struct {
		name     string
		rawFlags []string
		check    func(*testing.T, *TestOptions)
		wantErr  bool
	}{
		{
			name:     "string flag with value",
			rawFlags: []string{"--string", "test-value"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.Equal(t, "test-value", opts.StringFlag)
			},
		},
		{
			name:     "string pointer flag with value",
			rawFlags: []string{"--string-ptr", "ptr-value"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.NotNil(t, opts.StringPtr)
				assert.Equal(t, "ptr-value", *opts.StringPtr)
			},
		},
		{
			name:     "string flag without value",
			rawFlags: []string{"--string"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &TestOptions{}
			err := Parse(tt.rawFlags, opts)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tt.check != nil {
				tt.check(t, opts)
			}
		})
	}
}

func TestParse_SliceFlags(t *testing.T) {
	tests := []struct {
		name     string
		rawFlags []string
		expected []string
	}{
		{
			name:     "single value",
			rawFlags: []string{"--slice", "val1"},
			expected: []string{"val1"},
		},
		{
			name:     "multiple space-separated values",
			rawFlags: []string{"--slice", "val1", "val2", "val3"},
			expected: []string{"val1", "val2", "val3"},
		},
		{
			name:     "values stop at next flag",
			rawFlags: []string{"--slice", "val1", "val2", "--bool-flag"},
			expected: []string{"val1", "val2"},
		},
		{
			name:     "empty slice when no values",
			rawFlags: []string{"--slice", "--bool-flag"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &TestOptions{}
			err := Parse(tt.rawFlags, opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, opts.SliceFlag)
		})
	}
}

func TestParse_CustomTypeWithUnmarshalText(t *testing.T) {
	tests := []struct {
		name     string
		rawFlags []string
		expected []string
	}{
		{
			name:     "comma-separated values",
			rawFlags: []string{"--custom", "a,b,c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "single value",
			rawFlags: []string{"--custom", "single"},
			expected: []string{"single"},
		},
		{
			name:     "empty value",
			rawFlags: []string{"--custom", ""},
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &TestOptions{}
			err := Parse(tt.rawFlags, opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, []string(opts.CustomFlag))
		})
	}
}

func TestParse_UnknownFlags(t *testing.T) {
	tests := []struct {
		name     string
		rawFlags []string
		check    func(*testing.T, *TestOptions)
	}{
		{
			name:     "unknown flag ignored",
			rawFlags: []string{"--unknown", "--bool-flag"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.BoolFlag)
			},
		},
		{
			name:     "unknown flag with value ignored",
			rawFlags: []string{"--unknown", "value", "--bool-flag"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.True(t, opts.BoolFlag)
			},
		},
		{
			name:     "mixed known and unknown flags",
			rawFlags: []string{"--string", "test", "--unknown", "ignored", "--bool-flag"},
			check: func(t *testing.T, opts *TestOptions) {
				t.Helper()
				assert.Equal(t, "test", opts.StringFlag)
				assert.True(t, opts.BoolFlag)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &TestOptions{}
			err := Parse(tt.rawFlags, opts)
			assert.NoError(t, err)
			tt.check(t, opts)
		})
	}
}

func TestParse_MixedFlags(t *testing.T) {
	rawFlags := []string{
		"--bool-flag",
		"--string", "str-val",
		"--slice", "a", "b", "c",
		"--custom", "x,y,z",
		"-b",
		"--unknown", "ignored",
	}

	opts := &TestOptions{}
	err := Parse(rawFlags, opts)

	assert.NoError(t, err)
	assert.True(t, opts.BoolFlag)
	assert.True(t, opts.ShortFlag)
	assert.Equal(t, "str-val", opts.StringFlag)
	assert.Equal(t, []string{"a", "b", "c"}, opts.SliceFlag)
	assert.Equal(t, []string{"x", "y", "z"}, []string(opts.CustomFlag))
}

func TestParse_EmbeddedStructs(t *testing.T) {
	type Embedded struct {
		EmbeddedFlag bool `arg:"--embedded"`
	}

	type Parent struct {
		Embedded
		ParentFlag bool `arg:"--parent"`
	}

	rawFlags := []string{"--embedded", "--parent"}
	opts := &Parent{}
	err := Parse(rawFlags, opts)

	assert.NoError(t, err)
	assert.True(t, opts.EmbeddedFlag)
	assert.True(t, opts.ParentFlag)
}

func TestParse_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		dest    interface{}
		wantErr bool
	}{
		{
			name:    "nil pointer",
			dest:    nil,
			wantErr: true,
		},
		{
			name:    "not a pointer",
			dest:    TestOptions{},
			wantErr: true,
		},
		{
			name:    "pointer to non-struct",
			dest:    new(string),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Parse([]string{}, tt.dest)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
