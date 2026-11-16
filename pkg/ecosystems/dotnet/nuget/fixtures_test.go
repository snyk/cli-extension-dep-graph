package nuget

// packagesConfigManifest is a .NET Framework manifest that needs no .csproj:
// the targetFramework attributes NuGet writes are enough to name a runtime.
const packagesConfigManifest = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="10.0.3" targetFramework="net45" />
  <package id="jQuery" version="3.2.1" targetFramework="net45" />
</packages>`

// projectJSONManifest carries no framework hint of its own, so a project.json
// only resolves with a .csproj beside it.
const projectJSONManifest = `{"dependencies": {"Newtonsoft.Json": "8.0.3", "RouteMagic": "1.3"}}`

const csprojNet45 = `<Project><PropertyGroup><TargetFramework>net45</TargetFramework></PropertyGroup></Project>`

// singleTargetAssets is a valid net8.0 assets file with one direct dependency
// and one transitive one. It stands in wherever a test needs a resolvable
// project rather than a specific graph shape.
const singleTargetAssets = `{
  "version": 3,
  "targets": {
    "net8.0": {
      "Newtonsoft.Json/13.0.3": {
        "type": "package",
        "dependencies": { "System.Buffers": "4.5.1" }
      },
      "System.Buffers/4.5.1": { "type": "package" }
    }
  },
  "projectFileDependencyGroups": {
    "net8.0": [ "Newtonsoft.Json >= 13.0.3" ]
  },
  "project": {
    "version": "1.2.3",
    "restore": { "projectName": "FromAssetsFile" },
    "frameworks": { "net8.0": { "targetAlias": "net8.0" } }
  }
}`

// multiTargetAssets targets two frameworks, resolving a different version of
// the same package for each.
const multiTargetAssets = `{
  "version": 3,
  "targets": {
    "net6.0": { "Newtonsoft.Json/13.0.1": { "type": "package" } },
    "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } }
  },
  "projectFileDependencyGroups": {
    "net6.0": [ "Newtonsoft.Json >= 13.0.1" ],
    "net8.0": [ "Newtonsoft.Json >= 13.0.1" ]
  },
  "project": {
    "version": "1.0.0",
    "frameworks": {
      "net6.0": { "targetAlias": "net6.0" },
      "net8.0": { "targetAlias": "net8.0" }
    }
  }
}`

// namedProjectJSON records its own project name.
const namedProjectJSON = `{"dependencies": {"Newtonsoft.Json": "8.0.3"},
  "project": { "restore": { "projectName": "FromProjectJSON" } }}`

// scanRootName names the directory each identity case scans. The legacy CLI
// names every project after it, so it is fixed rather than a random temp dir name.
const scanRootName = "scan-root"
