package ecosystems

import (
	"errors"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyConfigFlags(t *testing.T) {
	tests := []struct {
		name       string
		values     map[string]interface{}
		wantBool   bool
		wantString string
	}{
		{name: "absent values preserve targets", wantBool: true, wantString: "raw"},
		{name: "explicit zero values override targets", values: map[string]interface{}{"bool": false, "string": ""}},
		{name: "alias supplies absent canonical value", values: map[string]interface{}{"alias": "alias-value"}, wantBool: true, wantString: "alias-value"},
		{name: "canonical value wins", values: map[string]interface{}{"string": "canonical", "alias": "alias-value"}, wantBool: true, wantString: "canonical"},
		{name: "empty canonical value wins", values: map[string]interface{}{"string": "", "alias": "alias-value"}, wantBool: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			for key, value := range tt.values {
				cfg.Set(key, value)
			}
			boolValue, stringValue := true, "raw"

			err := applyConfigFlags(cfg,
				boolFlag("bool", &boolValue),
				stringFlag("string", &stringValue, "alias"),
			)

			require.NoError(t, err)
			assert.Equal(t, tt.wantBool, boolValue)
			assert.Equal(t, tt.wantString, stringValue)
		})
	}
}

func TestApplyConfigFlagsParsedString(t *testing.T) {
	parseErr := errors.New("invalid value")
	tests := []struct {
		name       string
		set        bool
		parseErr   error
		wantValue  int
		wantCalled bool
		wantLater  bool
	}{
		{name: "absent value skips parsing", wantValue: 7, wantLater: true},
		{name: "parsed value replaces target", set: true, wantValue: 42, wantCalled: true, wantLater: true},
		{name: "parse error preserves target and stops later bindings", set: true, parseErr: parseErr, wantValue: 7, wantCalled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			if tt.set {
				cfg.Set("parsed", "42")
			}
			cfg.Set("later", true)
			value, called, later := 7, false, false
			parse := func(raw string) (int, error) {
				called = true
				assert.Equal(t, "42", raw)
				return 42, tt.parseErr
			}

			err := applyConfigFlags(cfg,
				parsedStringFlag("parsed", &value, parse),
				boolFlag("later", &later),
			)

			if tt.parseErr != nil {
				require.ErrorIs(t, err, tt.parseErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantValue, value)
			assert.Equal(t, tt.wantCalled, called)
			assert.Equal(t, tt.wantLater, later)
		})
	}
}

func TestApplyConfigFlagsNonEmptyString(t *testing.T) {
	tests := []struct {
		name         string
		set          bool
		value        string
		defaultValue string
		want         string
		wantSame     bool
	}{
		{name: "absent value preserves pointer", want: "raw", wantSame: true},
		{name: "empty value preserves pointer", set: true, want: "raw", wantSame: true},
		{name: "nonempty value replaces pointer", set: true, value: "configured", want: "configured"},
		{name: "nonempty default applies without IsSet", defaultValue: "default", want: "default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			if tt.set {
				cfg.Set("file", tt.value)
			}
			if tt.defaultValue != "" {
				cfg.AddDefaultValue("file", configuration.StandardDefaultValueFunction(tt.defaultValue))
				require.False(t, cfg.IsSet("file"))
			}
			raw := "raw"
			target := &raw

			err := applyConfigFlags(cfg, nonEmptyStringFlag("file", &target))

			require.NoError(t, err)
			require.NotNil(t, target)
			assert.Equal(t, tt.want, *target)
			if tt.wantSame {
				assert.Same(t, &raw, target)
			}
		})
	}
}
