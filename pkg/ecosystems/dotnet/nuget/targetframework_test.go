package nuget

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToReadableFramework(t *testing.T) {
	tests := []struct {
		moniker string
		name    string
		version string
	}{
		{"net45", ".NETFramework", "45"},
		{"net40", ".NETFramework", "40"},
		{"net461", ".NETFramework", "461"},
		// net4 has no second digit, so it is allowed by name rather than by
		// the pattern every other moniker goes through.
		{"net4", ".NETFramework", "4"},
		// The <TargetFrameworkVersion> spelling a non-SDK .csproj uses.
		{"v4.6.1", ".NETFramework", "4.6.1"},
		{"v4.5", ".NETFramework", "4.5"},
		{"netcoreapp2.0", ".NETCore", "2.0"},
		{"netcoreapp3.1", ".NETCore", "3.1"},
		{"netstandard2.0", ".NETStandard", "2.0"},
		{"netstandard1.6", ".NETStandard", "1.6"},
		// `net` is tried before `netcoreapp` and `netstandard`, and only does
		// not swallow them because a digit has to follow the prefix.
		{"net5.0", ".NETFramework", "5.0"},
	}

	for _, test := range tests {
		t.Run(test.moniker, func(t *testing.T) {
			framework, ok := toReadableFramework(test.moniker)
			require.True(t, ok)

			assert.Equal(t, test.name, framework.name)
			assert.Equal(t, test.version, framework.version)
			assert.Equal(t, test.moniker, framework.original, "the moniker is reported as written")
		})
	}
}

func TestToReadableFramework_Rejects(t *testing.T) {
	// Every one of these leaves a project unresolved rather than resolved under
	// a guessed framework, which is snyk-nuget-plugin's behavior too.
	for _, moniker := range []string{
		"",
		"net",
		"netcoreapp",
		// A platform-specific moniker. Only SDK-style projects have these, and
		// those are resolved from project.assets.json instead.
		"net8.0-windows",
		// The full .NET Framework 2.0 build number: too many parts to match.
		"v2.0.50727",
		"notaframework",
	} {
		t.Run(moniker, func(t *testing.T) {
			_, ok := toReadableFramework(moniker)
			assert.False(t, ok)
		})
	}
}

func TestCsprojTargetFramework(t *testing.T) {
	tests := []struct {
		name    string
		csproj  string
		want    string
		wantErr bool
	}{
		{
			name: "SDK-style TargetFramework",
			csproj: `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>netcoreapp2.0</TargetFramework></PropertyGroup>
</Project>`,
			want: "netcoreapp2.0",
		},
		{
			name: "non-SDK TargetFrameworkVersion, with the MSBuild namespace",
			csproj: `<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="12.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup><TargetFrameworkVersion>v4.6.1</TargetFrameworkVersion></PropertyGroup>
</Project>`,
			want: "v4.6.1",
		},
		{
			name: "TargetFrameworkVersion outranks TargetFramework in the same group",
			csproj: `<Project>
  <PropertyGroup>
    <TargetFramework>netcoreapp2.0</TargetFramework>
    <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>
  </PropertyGroup>
</Project>`,
			want: "v4.5",
		},
		{
			name: "a property group naming no framework is skipped, not fatal",
			csproj: `<Project>
  <PropertyGroup><AssemblyName>App</AssemblyName></PropertyGroup>
  <PropertyGroup><TargetFramework>net45</TargetFramework></PropertyGroup>
</Project>`,
			want: "net45",
		},
		{
			name: "the first moniker of a semicolon-separated TargetFrameworks wins",
			csproj: `<Project>
  <PropertyGroup><TargetFrameworks>net45;netstandard2.0</TargetFrameworks></PropertyGroup>
</Project>`,
			want: "net45",
		},
		{
			name: "an unrecognized moniker is passed over rather than ending the search",
			csproj: `<Project>
  <PropertyGroup><TargetFrameworks>net8.0-windows;net45</TargetFrameworks></PropertyGroup>
</Project>`,
			want: "net45",
		},
		{
			name: "a project naming no framework at all reports none",
			csproj: `<Project>
  <PropertyGroup><AssemblyName>App</AssemblyName></PropertyGroup>
</Project>`,
		},
		{
			name:    "unparseable XML is an error, not a silent miss",
			csproj:  `<Project><PropertyGroup>`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "App.csproj"), []byte(test.csproj), 0o600))

			framework, ok, err := csprojTargetFramework(dir)
			if test.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.want != "", ok)
			assert.Equal(t, test.want, framework.original)
		})
	}
}

func TestCsprojTargetFramework_UTF16(t *testing.T) {
	dir := t.TempDir()
	csproj := `<?xml version="1.0" encoding="utf-16"?>
<Project><PropertyGroup><TargetFrameworkVersion>v4.5</TargetFrameworkVersion></PropertyGroup></Project>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "App.csproj"), utf16LE(csproj), 0o600))

	framework, ok, err := csprojTargetFramework(dir)
	require.NoError(t, err)
	require.True(t, ok, "a UTF-16 .csproj is still a .csproj — Visual Studio has written them for years")
	assert.Equal(t, "v4.5", framework.original)
}

func TestCsprojTargetFramework_OnlyCsproj(t *testing.T) {
	dir := t.TempDir()
	// snyk-nuget-plugin looks for *.csproj and nothing else, so a Visual Basic
	// or F# project falls back to whatever the manifest itself can offer.
	// Widening this would resolve projects the CLI cannot resolve today.
	for _, name := range []string{"App.vbproj", "App.fsproj"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name),
			[]byte(`<Project><PropertyGroup><TargetFramework>net45</TargetFramework></PropertyGroup></Project>`), 0o600))
	}

	_, ok, err := csprojTargetFramework(dir)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestCsprojTargetFramework_NoProjectFile(t *testing.T) {
	_, ok, err := csprojTargetFramework(t.TempDir())
	require.NoError(t, err, "a project with no .csproj is ordinary, not broken")
	assert.False(t, ok)
}

func TestMinimumTargetFramework(t *testing.T) {
	tests := []struct {
		name     string
		monikers []string
		want     string
	}{
		{
			name: "no hints at all",
		},
		{
			// A plain string comparison, as upstream's reduce is — not a
			// version comparison, which would also pick net452 here but would
			// differ elsewhere.
			name:     "the lowest moniker wins",
			monikers: []string{"net461", "net452"},
			want:     "net452",
		},
		{
			name:     "repeats collapse",
			monikers: []string{"net45", "net45", "net45"},
			want:     "net45",
		},
		{
			name:     "net4 sorts below net40",
			monikers: []string{"net40", "net4"},
			want:     "net4",
		},
		{
			// The minimum is taken first and mapped second, so an unmappable
			// minimum leaves the project unresolved rather than falling through
			// to the next-lowest moniker.
			name:     "an unrecognized minimum is not skipped over",
			monikers: []string{"net45", "aaa1.0"},
			want:     "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			framework, ok := minimumTargetFramework(test.monikers)
			assert.Equal(t, test.want != "", ok)
			assert.Equal(t, test.want, framework.original)
		})
	}
}

func TestDetectTargetFramework_CsprojBeatsManifestHints(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "App.csproj"),
		[]byte(`<Project><PropertyGroup><TargetFramework>netcoreapp2.0</TargetFramework></PropertyGroup></Project>`), 0o600))

	manifest := &frameworkManifest{frameworkHints: []string{"net461"}}

	framework, ok, err := detectTargetFramework(dir, manifest)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "netcoreapp2.0", framework.original,
		"the project file declares the framework; the manifest only records what NuGet installed for")
}

func TestDetectTargetFramework_FallsBackToManifestHints(t *testing.T) {
	manifest := &frameworkManifest{frameworkHints: []string{"net461", "net452"}}

	framework, ok, err := detectTargetFramework(t.TempDir(), manifest)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "net452", framework.original)
}

func TestDetectTargetFramework_NoneAvailable(t *testing.T) {
	// project.json carries no hints at all, so this is what every project.json
	// without a .csproj beside it looks like.
	_, ok, err := detectTargetFramework(t.TempDir(), &frameworkManifest{})
	require.NoError(t, err)
	assert.False(t, ok)
}

// utf16LE encodes s as UTF-16 little-endian with a byte order mark, the way
// Visual Studio has written project files.
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))

	out := append([]byte{}, bomUTF16LE...)
	for _, unit := range units {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}

	return out
}

// snyk-nuget-plugin matches project files with a case-sensitive regex, so a
// project file spelled any other way is invisible to the CLI. Finding one here
// would resolve a project that fails today.
func TestCsprojTargetFramework_ExtensionIsCaseSensitive(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "App.CSPROJ"),
		[]byte(`<Project><PropertyGroup><TargetFramework>net45</TargetFramework></PropertyGroup></Project>`), 0o600))

	_, ok, err := csprojTargetFramework(dir)
	require.NoError(t, err)
	assert.False(t, ok)
}
