package bazel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseArtifactName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected mavenArtifact
	}{
		{
			name:     "empty string returns empty",
			input:    "",
			expected: mavenArtifact{},
		},
		{
			name:     "five or more colon-separated segments returns empty",
			input:    "a:b:c:d:e",
			expected: mavenArtifact{},
		},
		{
			name:     "six segments returns empty",
			input:    "a:b:c:d:e:f",
			expected: mavenArtifact{},
		},
		{
			name:  "two segments — standard group:artifact",
			input: "com.google.guava:guava",
			expected: mavenArtifact{
				label: "com_google_guava_guava",
				name:  "com.google.guava:guava",
			},
		},
		{
			name:  "two segments — hyphens in coordinates",
			input: "org.jetbrains.kotlin:kotlin-stdlib",
			expected: mavenArtifact{
				label: "org_jetbrains_kotlin_kotlin_stdlib",
				name:  "org.jetbrains.kotlin:kotlin-stdlib",
			},
		},
		{
			name:  "three segments — packaging dropped from label and name",
			input: "androidx.fragment:fragment:aar",
			expected: mavenArtifact{
				label: "androidx_fragment_fragment",
				name:  "androidx.fragment:fragment",
			},
		},
		{
			name:  "three segments — pom packaging",
			input: "com.example:parent:pom",
			expected: mavenArtifact{
				label: "com_example_parent",
				name:  "com.example:parent",
			},
		},
		{
			name:  "four segments — classifier in label only",
			input: "org.junit.jupiter:junit-jupiter-api:jar:test",
			expected: mavenArtifact{
				label: "org_junit_jupiter_junit_jupiter_api_test",
				name:  "org.junit.jupiter:junit-jupiter-api",
			},
		},
		{
			name:  "four segments — classifier with dots",
			input: "g:a:jar:javadoc",
			expected: mavenArtifact{
				label: "g_a_javadoc",
				name:  "g:a",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := parseArtifactName(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}
