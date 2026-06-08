package modules

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoListEnv_OverridesAreSet(t *testing.T) {
	parent := []string{
		"HOME=/home/test",
		"PATH=/usr/bin",
		"GOPROXY=https://proxy.golang.org",
		"GOSUMDB=sum.golang.org",
		"GOFLAGS=-mod=mod",
	}

	got := goListEnv(parent)

	// Build a map for easy assertion on final values.
	m := make(map[string]string)
	for _, kv := range got {
		k := envKey(kv)
		m[k] = kv[len(k)+1:]
	}

	assert.Equal(t, "off", m["GOPROXY"], "GOPROXY must be forced off")
	assert.Equal(t, "off", m["GOSUMDB"], "GOSUMDB must be forced off")
	assert.Equal(t, "", m["GOFLAGS"], "GOFLAGS must be cleared")

	// Unrelated env passes through.
	assert.Equal(t, "/home/test", m["HOME"])
	assert.Equal(t, "/usr/bin", m["PATH"])
}

func TestGoListEnv_NoDuplicateKeys(t *testing.T) {
	parent := []string{"GOPROXY=https://proxy", "GOPROXY=other"}
	got := goListEnv(parent)

	var goproxyCount int
	for _, kv := range got {
		if envKey(kv) == "GOPROXY" {
			goproxyCount++
		}
	}
	assert.Equal(t, 1, goproxyCount, "GOPROXY appears exactly once")
}

func TestGoListEnv_EmptyParent(t *testing.T) {
	got := goListEnv(nil)
	sort.Strings(got)
	assert.Equal(t, []string{"GOFLAGS=", "GOPROXY=off", "GOSUMDB=off"}, got)
}

func TestEnvKey(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"FOO=bar", "FOO"},
		{"FOO=", "FOO"},
		{"FOO", "FOO"},
		{"", ""},
		{"A=B=C", "A"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, envKey(tt.in), tt.in)
	}
}
