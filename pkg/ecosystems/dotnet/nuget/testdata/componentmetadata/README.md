# componentmetadata fixture

A real `dotnet restore` (SDK 10.0.101, nuget.org, 2026-11-23) of `App.csproj`, a
net8.0 project referencing Castle.Core 4.4.1, trimmed for the
`--include-component-metadata` tests in `component_metadata_test.go`.

- `obj/project.assets.json` keeps two packages, Castle.Core 4.4.1 and
  System.Collections.Specialized 4.3.0, with Castle.Core's other dependencies
  removed. `packageFolders` and the restore paths are placeholders the tests
  replace with temp folders. The `libraries[*].sha512` values are real and are
  the content hashes, which the resolver must not emit.
- `packages/<id>/<version>/` holds the real `.nupkg.sha512` and
  `.nupkg.metadata` NuGet wrote. The `.nupkg` files are left out for size. The
  Castle.Core `.nupkg.sha512` decodes to the SHA-512 of the file nuget.org
  serves at
  `https://api.nuget.org/v3-flatcontainer/castle.core/4.4.1/castle.core.4.4.1.nupkg`,
  checked when the fixture was made.

There is no upstream snyk-nuget-plugin golden for these labels. The
expectations come from sbom-export's label contract (`hash:sha-512` as
lowercase hex, `distribution:url` sanitized) and from this real restore.
