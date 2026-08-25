package nuget

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Document order decides which `targets` key a framework maps to and which
// sibling edges get pruned, so a decode that loses it changes the graph. Go map
// iteration is randomized, which is what makes this worth pinning down.
func TestOrderedMap_PreservesDocumentOrder(t *testing.T) {
	var m orderedMap[int]
	require.NoError(t, json.Unmarshal([]byte(`{"zulu":1,"alpha":2,"mike":3}`), &m))

	assert.Equal(t, []string{"zulu", "alpha", "mike"}, m.Keys(), "not sorted, not randomized: as written")
	assert.Equal(t, 3, m.Len())

	value, ok := m.Get("alpha")
	assert.True(t, ok)
	assert.Equal(t, 2, value)

	_, ok = m.Get("absent")
	assert.False(t, ok)
}

func TestOrderedMap_EdgeCases(t *testing.T) {
	t.Run("null decodes to empty", func(t *testing.T) {
		var m orderedMap[int]
		require.NoError(t, json.Unmarshal([]byte(`null`), &m))
		assert.Zero(t, m.Len())
		assert.Empty(t, m.Keys())
	})

	t.Run("empty object", func(t *testing.T) {
		var m orderedMap[int]
		require.NoError(t, json.Unmarshal([]byte(`{}`), &m))
		assert.Zero(t, m.Len())
	})

	t.Run("a repeated key keeps its first position", func(t *testing.T) {
		var m orderedMap[int]
		require.NoError(t, json.Unmarshal([]byte(`{"a":1,"b":2,"a":3}`), &m))

		assert.Equal(t, []string{"a", "b"}, m.Keys())

		value, _ := m.Get("a")
		assert.Equal(t, 3, value, "the last value wins, as it would in JSON")
	})

	t.Run("a non-object is rejected", func(t *testing.T) {
		var m orderedMap[int]
		require.Error(t, json.Unmarshal([]byte(`["a"]`), &m))
	})

	t.Run("a bad value is rejected", func(t *testing.T) {
		var m orderedMap[int]
		err := json.Unmarshal([]byte(`{"a":"not a number"}`), &m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"a"`, "the failing key is named")
	})
}

func TestReadProjectAssets(t *testing.T) {
	t.Run("reads a valid file", func(t *testing.T) {
		dir := t.TempDir()
		path := write(t, dir, projectAssetsFile, singleTargetAssets)

		assets, err := readProjectAssets(path, projectAssetsFile)
		require.NoError(t, err)
		assert.Equal(t, "1.2.3", assets.Project.Version)
		assert.Equal(t, []string{"net8.0"}, assets.targetFrameworks())
	})

	// A project we were asked to scan but whose restore output has gone missing
	// is the case the CLI hits when --file points at a stale path.
	t.Run("a missing file names the remedy", func(t *testing.T) {
		absent := filepath.Join(t.TempDir(), projectAssetsFile)

		_, err := readProjectAssets(absent, filepath.Join(objDir, projectAssetsFile))
		require.Error(t, err)

		detail := detailOf(t, err)
		assert.Contains(t, detail, "dotnet restore")

		// The user is shown the path relative to the scan root; quoting the
		// absolute one leaks the build agent's layout into CI logs.
		assert.Contains(t, detail, filepath.Join(objDir, projectAssetsFile))
		assert.NotContains(t, detail, absent)
	})

	// A file that is present but cannot be opened is a filesystem problem, and
	// telling the user to re-run `dotnet restore` would send them the wrong way.
	t.Run("an unreadable file is reported as a read failure, not a missing one", func(t *testing.T) {
		dir := t.TempDir()
		path := write(t, dir, projectAssetsFile, singleTargetAssets)
		require.NoError(t, os.Chmod(path, 0o000))
		// Restored so t.TempDir cleanup can remove it.
		t.Cleanup(func() {
			require.NoError(t, os.Chmod(path, 0o600))
		})

		if _, probe := os.ReadFile(path); probe == nil {
			t.Skip("filesystem or user ignores mode bits, so the read cannot be made to fail")
		}

		_, err := readProjectAssets(path, projectAssetsFile)
		require.Error(t, err)

		detail := detailOf(t, err)
		assert.Contains(t, detail, "could not be opened")
		assert.NotContains(t, detail, "dotnet restore", "restore does not fix a permissions problem")
		// The cause is named without the absolute path the OS appends.
		assert.Contains(t, detail, "permission denied")
		assert.NotContains(t, detail, dir)
	})
}

// validate mirrors validateManifest in snyk-nuget-plugin, so a file it refuses
// is refused here for the same reason.
func TestProjectAssets_Validate(t *testing.T) {
	tests := map[string]struct {
		content string
		detail  string
	}{
		"no project section": {
			content: `{"targets":{"net8.0":{}}}`,
			detail:  "No project section was found",
		},
		"null project section": {
			content: `{"targets":{"net8.0":{}},"project":null}`,
			detail:  "No project section was found",
		},
		"no frameworks": {
			content: `{"targets":{"net8.0":{}},"project":{"version":"1.0.0"}}`,
			detail:  "No target frameworks were found",
		},
		"empty frameworks": {
			content: `{"targets":{"net8.0":{}},"project":{"frameworks":{}}}`,
			detail:  "No target frameworks were found",
		},
		"no targets": {
			content: `{"project":{"frameworks":{"net8.0":{}}}}`,
			detail:  "No targets were found",
		},
		"empty targets": {
			content: `{"targets":{},"project":{"frameworks":{"net8.0":{}}}}`,
			detail:  "No targets were found",
		},
		// The moniker becomes the target runtime, which is part of the project's
		// identity, so a framework without one cannot be carried.
		"a framework with no name": {
			content: `{"targets":{"net8.0":{}},"project":{"frameworks":{"":{}}}}`,
			detail:  "has no name",
		},
		"a framework whose alias is empty falls back to its key": {
			content: `{"targets":{"net8.0":{}},"project":{"frameworks":{"net8.0":{"targetAlias":""}}}}`,
			detail:  "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := assetsFrom(t, tt.content).validate("assets.json")

			if tt.detail == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, detailOf(t, err), tt.detail)
		})
	}

	// An empty project section is *not* a validation failure — a project with no
	// direct dependencies is legitimate, and neither project.version nor
	// project.restore is required.
	t.Run("accepts a minimal project", func(t *testing.T) {
		content := `{"targets":{"net8.0":{}},"project":{"frameworks":{"net8.0":{}}}}`
		require.NoError(t, assetsFrom(t, content).validate("assets.json"))
	})
}

// The alias is the short moniker users recognize; the raw key can carry a
// platform version they never wrote down.
func TestProjectAssets_TargetFrameworks(t *testing.T) {
	assets := assetsFrom(t, `{
      "project": {
        "frameworks": {
          "net7.0-windows7.0": { "targetAlias": "net7.0-windows" },
          "netcoreapp1.1": {},
          "net8.0": { "targetAlias": "net8.0" }
        }
      }
    }`)

	assert.Equal(t, []string{"net7.0-windows", "netcoreapp1.1", "net8.0"}, assets.targetFrameworks(),
		"the alias wins where present, and declaration order is preserved")
}

func TestAssetsFrameworkName(t *testing.T) {
	tests := map[string]string{
		// .NET Standard.
		"netstandard2.0": ".NETStandard,Version=v2.0",
		"netstandard2.1": ".NETStandard,Version=v2.1",
		"netstandard1.6": ".NETStandard,Version=v1.6",
		// .NET Core.
		"netcoreapp1.1": ".NETCoreApp,Version=v1.1",
		"netcoreapp3.1": ".NETCoreApp,Version=v3.1",
		// .NET Framework, whose version is written without dots.
		"net48":  ".NETFramework,Version=v4.8",
		"net472": ".NETFramework,Version=v4.7.2",
		"net481": ".NETFramework,Version=v4.8.1",
		"net35":  ".NETFramework,Version=v3.5",
		"net20":  ".NETFramework,Version=v2.0",
		// A bare major, which NuGet supports by design (NuGet/Home#1371).
		"net4": ".NETFramework,Version=v4.0",

		// net5.0 and later use the short form in both sections. The dot is what
		// keeps them out of the .NETFramework rule.
		"net5.0":  "net5.0",
		"net8.0":  "net8.0",
		"net10.0": "net10.0",

		// Platform-qualified monikers are matched by prefix, not remapped.
		"net8.0-windows": "net8.0-windows",

		// The remainder has to be a version. "netstandardapp1.5" is a real
		// moniker, and remapping it would send the matcher looking for
		// ".NETStandard,Version=vapp1.5", which exists nowhere.
		"netstandardapp1.5": "netstandardapp1.5",
		"netstandard":       "netstandard",
		"netcoreapp":        "netcoreapp",
		"net":               "net",
		// Too many digits to be a .NET Framework version.
		"net4721": "net4721",
		// Already long-form.
		".NETStandard,Version=v2.1": ".NETStandard,Version=v2.1",
	}

	for framework, want := range tests {
		t.Run(framework, func(t *testing.T) {
			assert.Equal(t, want, assetsFrameworkName(framework))
		})
	}
}

func TestProjectAssets_MatchTargetsKey(t *testing.T) {
	tests := map[string]struct {
		targets   []string
		framework string
		want      string
	}{
		"exact match": {
			targets:   []string{"net8.0"},
			framework: "net8.0",
			want:      "net8.0",
		},
		"prefers the exact key over a runtime-specific one": {
			targets:   []string{"net6.0/linux-x64", "net6.0"},
			framework: "net6.0",
			want:      "net6.0",
		},
		"netstandard is remapped to the long moniker": {
			targets:   []string{".NETStandard,Version=v2.1"},
			framework: "netstandard2.1",
			want:      ".NETStandard,Version=v2.1",
		},
		"a longer key matching the framework as a prefix": {
			targets:   []string{"net8.0-windows7.0"},
			framework: "net8.0-windows",
			want:      "net8.0-windows7.0",
		},
		"a shorter key the framework extends": {
			targets:   []string{"net6.0-windows10.0.19041"},
			framework: "net6.0-windows10.0.19041.0",
			want:      "net6.0-windows10.0.19041",
		},
		// The longest match wins. Taking the first would hand net8.0-windows the
		// plain net8.0 package set and drop its Windows-only packages.
		"prefers the longest match over a shorter sibling": {
			targets:   []string{"net8.0", "net8.0-windows7.0"},
			framework: "net8.0-windows",
			want:      "net8.0-windows7.0",
		},
		"longest match regardless of document order": {
			targets:   []string{"net8.0-windows7.0", "net8.0"},
			framework: "net8.0-windows",
			want:      "net8.0-windows7.0",
		},
		"netstandard remap still prefix-matches a runtime-specific key": {
			targets:   []string{".NETStandard,Version=v2.0/linux-x64"},
			framework: "netstandard2.0",
			want:      ".NETStandard,Version=v2.0/linux-x64",
		},
		"falls back to the sole key when nothing matches": {
			targets:   []string{".NETCoreApp,Version=v1.1"},
			framework: "netcoreapp1.1",
			want:      ".NETCoreApp,Version=v1.1",
		},
		// The pre-net5 families are all derived, so a multi-target project mixing
		// them resolves each framework against its own packages instead of
		// falling through to the positional fallback.
		"netcoreapp and net4x alongside each other": {
			targets:   []string{".NETCoreApp,Version=v3.1", ".NETFramework,Version=v4.7.2"},
			framework: "net472",
			want:      ".NETFramework,Version=v4.7.2",
		},
		"the sibling of that pair resolves to its own packages": {
			targets:   []string{".NETCoreApp,Version=v3.1", ".NETFramework,Version=v4.7.2"},
			framework: "netcoreapp3.1",
			want:      ".NETCoreApp,Version=v3.1",
		},
		// With more than one target and nothing derivable there is no safe
		// guess: returning another framework's key would report its packages
		// under this framework's name and drop this one's entirely.
		"no fallback when several targets could be meant": {
			targets:   []string{"net8.0", "some-vendor-moniker"},
			framework: "another-vendor-moniker",
			want:      "",
		},
		// A mapping that does not apply to this project must not rule out the
		// name the project actually declared. Two targets, so the single-target
		// fallback cannot mask a matcher that only searches the remapped form.
		"the declared name still matches when its remap does not": {
			targets:   []string{"net472-custom", "net8.0"},
			framework: "net472",
			want:      "net472-custom",
		},
		"no targets at all": {
			targets:   nil,
			framework: "net8.0",
			want:      "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, targetsWithKeys(t, tt.targets).matchTargetsKey(tt.framework))
		})
	}
}

// targetsWithKeys builds an assets file whose `targets` section has the given
// keys, in the given order, each with no packages.
func targetsWithKeys(t *testing.T, keys []string) *projectAssets {
	t.Helper()

	entries := make([]string, len(keys))
	for i, key := range keys {
		encoded, err := json.Marshal(key)
		require.NoError(t, err)
		entries[i] = string(encoded) + `:{}`
	}

	content := `{"targets":{`
	for i, entry := range entries {
		if i > 0 {
			content += ","
		}
		content += entry
	}
	content += `}}`

	return assetsFrom(t, content)
}

func TestProjectAssets_DirectDependencies(t *testing.T) {
	t.Run("names are taken from the constraint strings", func(t *testing.T) {
		assets := assetsFrom(t, `{
          "projectFileDependencyGroups": {
            "net8.0": [ "Newtonsoft.Json >= 13.0.3", "Humanizer >= 2.14.1" ]
          }
        }`)

		assert.Equal(t, []string{"Newtonsoft.Json", "Humanizer"}, assets.directDependencies("net8.0"),
			"the declared constraint is dropped; the resolved version comes from targets")
	})

	t.Run("an absent section means no direct dependencies", func(t *testing.T) {
		assert.Empty(t, assetsFrom(t, `{}`).directDependencies("net8.0"))
	})

	// The section is keyed by the same moniker as `targets` in every file NuGet
	// writes, but the matcher can land on a runtime-specific key that the section
	// does not have. Upstream throws a TypeError here and takes down the whole
	// scan; a single-group project can be resolved instead.
	t.Run("falls back to the sole group", func(t *testing.T) {
		assets := assetsFrom(t, `{
          "projectFileDependencyGroups": { "net8.0": [ "Humanizer >= 2.14.1" ] }
        }`)

		assert.Equal(t, []string{"Humanizer"}, assets.directDependencies("net8.0/linux-x64"))
	})

	t.Run("no fallback when the group is ambiguous", func(t *testing.T) {
		assets := assetsFrom(t, `{
          "projectFileDependencyGroups": {
            "net6.0": [ "Humanizer >= 2.14.1" ],
            "net8.0": [ "Newtonsoft.Json >= 13.0.3" ]
          }
        }`)

		assert.Empty(t, assets.directDependencies("net9.0"),
			"guessing between frameworks would report the wrong dependency set")
	})

	// Upstream keys these by name, so a repeated entry collapses. Keeping both
	// would walk the package twice and hang a pruned leaf off the root.
	t.Run("a repeated dependency is reported once", func(t *testing.T) {
		assets := assetsFrom(t, `{
          "projectFileDependencyGroups": {
            "net8.0": [ "Newtonsoft.Json >= 13.0.3", "Humanizer >= 2.14.1", "Newtonsoft.Json >= 13.0.3" ]
          }
        }`)

		assert.Equal(t, []string{"Newtonsoft.Json", "Humanizer"}, assets.directDependencies("net8.0"))
	})

	t.Run("blank entries are skipped", func(t *testing.T) {
		assets := assetsFrom(t, `{"projectFileDependencyGroups":{"net8.0":["","Humanizer >= 2.14.1"]}}`)
		assert.Equal(t, []string{"Humanizer"}, assets.directDependencies("net8.0"))
	})
}

func TestResolvePackages(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": {
        "net8.0": {
          "Newtonsoft.Json/13.0.3": { "type": "package", "dependencies": { "System.Buffers": "4.5.1" } },
          "NoVersionKey": { "type": "package" }
        }
      }
    }`)

	target, ok := assets.Targets.Get("net8.0")
	require.True(t, ok)

	resolved := resolvePackages(&target)

	// Indexed by lowercased name so a differently-cased reference still finds it,
	// while the name and version reported are the ones on the targets key.
	pkg, ok := resolved["newtonsoft.json"]
	require.True(t, ok)
	assert.Equal(t, "Newtonsoft.Json", pkg.name)
	assert.Equal(t, "13.0.3", pkg.version)
	assert.Equal(t, []string{"System.Buffers"}, pkg.deps.Keys())

	assert.Len(t, resolved, 1, "a key with no version is not something the format produces; it is skipped")
}

// Upstream destructures `key.split('/')`, so a key with more components than
// name and version drops the rest rather than folding them into the version.
func TestResolvePackages_ExtraPathComponentsAreDropped(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": {
        "net8.0": {
          "CorePkg/2.0.0/extra": { "type": "package" }
        }
      }
    }`)

	target, ok := assets.Targets.Get("net8.0")
	require.True(t, ok)

	pkg, found := resolvePackages(&target)["corepkg"]
	require.True(t, found)
	assert.Equal(t, "CorePkg", pkg.name)
	assert.Equal(t, "2.0.0", pkg.version, "not 2.0.0/extra")
}

// Two keys differing only in case collapse to one package, and which one wins
// has to be the same on every run — a plain Go map would decide it by
// randomized iteration order.
func TestResolvePackages_CaseCollisionIsDeterministic(t *testing.T) {
	const content = `{
      "targets": {
        "net8.0": {
          "Newtonsoft.Json/13.0.3": { "type": "package" },
          "newtonsoft.json/9.0.1": { "type": "package" }
        }
      }
    }`

	for range 50 {
		target, ok := assetsFrom(t, content).Targets.Get("net8.0")
		require.True(t, ok)

		pkg, found := resolvePackages(&target)["newtonsoft.json"]
		require.True(t, found)

		// Last in document order wins, matching Object.entries upstream.
		assert.Equal(t, "newtonsoft.json", pkg.name)
		assert.Equal(t, "9.0.1", pkg.version)
	}
}

func TestIsFilteredPackage(t *testing.T) {
	tests := map[string]bool{
		"runtime":                                 true,
		"runtime.native.System.Net.Http":          true,
		"runtime.linux-x64.Microsoft.NETCore.App": true,
		"Newtonsoft.Json":                         false,
		// The prefix is matched case-sensitively, as upstream matches it.
		"Runtime.Native.System": false,
		"System.Runtime":        false,
	}

	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, want, isFilteredPackage(name))
		})
	}
}
