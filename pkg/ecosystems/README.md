# Ecosystems Package

The `ecosystems` package provides a unified plugin interface for discovering and building dependency graphs across multiple package managers and programming language ecosystems.

## Purpose

Modern software projects use diverse package managers (pip, npm, maven, gradle, etc.) to manage dependencies. Each ecosystem has its own format for declaring and resolving dependencies. This package standardizes how dependency graphs are discovered, built, and represented, regardless of the underlying package manager.

### Key Goals

1. **Unified Interface**: Provide a consistent API for dependency graph generation across all package managers
2. **Extensibility**: Make it easy to add support for new ecosystems without modifying core code
3. **Type Safety**: Leverage Go's type system to catch errors at compile time
4. **Testability**: Enable dependency injection and mocking for robust testing
5. **Ecosystem Isolation**: Keep ecosystem-specific logic contained within dedicated plugins

## Architecture

### Core Interface

Every plugin implements the `SCAPlugin` interface to:
- **Discover** dependency manifests in a directory (e.g., `requirements.txt`, `package.json`)
- **Resolve** dependencies using the ecosystem's native tooling
- **Build** a standardized dependency graph representation
- **Return** results with metadata about the analysis

## Data Structures

### DepGraph: Snyk Dependency Graph Format

The `SCAResult.DepGraph` field uses the standard Snyk dependency graph format from `github.com/snyk/dep-graph/go/pkg/depgraph`:

```go
import "github.com/snyk/dep-graph/go/pkg/depgraph"

type SCAResult struct {
    DepGraph *depgraph.DepGraph `json:"depGraph,omitempty"`
    Metadata Metadata           `json:"metadata"`
    Error    error              `json:"error,omitempty"`
}
```

#### DepGraph Structure

The `depgraph.DepGraph` type provides a standardized format for representing dependency graphs:

```json
{
  "schemaVersion": "1.3.0",
  "pkgManager": {
    "name": "pip"
  },
  "pkgs": [
    {
      "id": "root@0.0.0",
      "info": {
        "name": "root",
        "version": "0.0.0"
      }
    },
    {
      "id": "requests@2.31.0",
      "info": {
        "name": "requests",
        "version": "2.31.0"
      }
    }
  ],
  "graph": {
    "rootNodeId": "root-node",
    "nodes": [
      {
        "nodeId": "root-node",
        "pkgId": "root@0.0.0",
        "deps": [
          { "nodeId": "requests@2.31.0" }
        ]
      },
      {
        "nodeId": "requests@2.31.0",
        "pkgId": "requests@2.31.0",
        "deps": []
      }
    ]
  }
}
```

#### Key Components

| Field | Description |
|-------|-------------|
| `schemaVersion` | Version of the dep-graph schema (e.g., "1.3.0") |
| `pkgManager` | Package manager info with `name` (e.g., "pip", "npm") |
| `pkgs` | Array of all packages with `id` and `info` (name, version) |
| `graph.rootNodeId` | ID of the root node in the graph |
| `graph.nodes` | Array of nodes, each with `nodeId`, `pkgId`, and `deps` |

#### Building a DepGraph

Use the `depgraph.Builder` to construct dependency graphs:

```go
import "github.com/snyk/dep-graph/go/pkg/depgraph"

// Create a builder with package manager and root package info
builder, err := depgraph.NewBuilder(
    &depgraph.PkgManager{Name: "pip"},
    &depgraph.PkgInfo{Name: "root", Version: "0.0.0"},
)
if err != nil {
    return nil, err
}

// Add package nodes
builder.AddNode("requests@2.31.0", &depgraph.PkgInfo{
    Name:    "requests",
    Version: "2.31.0",
})

// Connect dependencies
rootNode := builder.GetRootNode()
err = builder.ConnectNodes(rootNode.NodeID, "requests@2.31.0")
if err != nil {
    return nil, err
}

// Build the final graph
depGraph := builder.Build()
```

### SCAResult: Analysis Output

```go
type SCAResult struct {
    DepGraph *depgraph.DepGraph `json:"depGraph,omitempty"`
    Metadata Metadata           `json:"metadata"`
    Error    error              `json:"error,omitempty"`
}
```

Each result contains:
- **DepGraph**: The complete dependency graph using Snyk's standard format
- **Metadata**: Context about the analysis (target file, runtime environment)
- **Error**: Any error encountered during analysis (optional)

### Metadata

```go
type Metadata struct {
    TargetFile string `json:"targetFile"`  // Path to the manifest file (e.g., "requirements.txt")
    Runtime    string `json:"runtime"`     // Runtime environment (e.g., "python@3.11.0")
}
```

Plugins return `PluginResult`, where:
* `Results` contains depgraphs and other data. Multiple findings are permitted to allow for workspaces and other scenarios where more than one project are found within an ecosytem.
* `ProcessedFiles` contains files that other plugins should not handle (either because the plugin has processed them directly, e.g. `uv.lock` for uv, or because it is associated with the handled project, e.g. `pyproject.toml` or `requirements.txt` associated with a uv project).

## Usage Examples

### Basic Usage

```go
import (
    "context"
    "fmt"
    "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
    "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
)

func main() {
    plugin := &pip.Plugin{}
    options := ecosystems.NewPluginOptions().
        WithTargetFile("requirements.txt")
    
    result, err := plugin.BuildDepGraphsFromDir(
        context.Background(),
        logger.Nop(),
        "/path/to/python/project",
        options,
    )
    if err != nil {
        // Handle error
    }
    
    for _, scaResult := range result.Results {
        if scaResult.Error != nil {
            fmt.Printf("Error analyzing %s: %v\n", scaResult.Metadata.TargetFile, scaResult.Error)
            continue
        }
        
        fmt.Printf("Target: %s\n", scaResult.Metadata.TargetFile)
        fmt.Printf("Runtime: %s\n", scaResult.Metadata.Runtime)
        fmt.Printf("Package Manager: %s\n", scaResult.DepGraph.PkgManager.Name)
        fmt.Printf("Total Packages: %d\n", len(scaResult.DepGraph.Pkgs))
    }
}
```

### Analyzing All Projects

```go
options := ecosystems.NewPluginOptions().
    WithAllProjects(true)

result, err := plugin.BuildDepGraphsFromDir(ctx, logger.Nop(), "/path/to/monorepo", options)
// Returns results for all requirements.txt files found
```

### Handling Errors in Results

```go
for _, result := range result.Results {
    if result.Error != nil {
        // Individual file failed, but others may have succeeded
        log.Printf("Failed to analyze %s: %v", result.Metadata.TargetFile, result.Error)
        continue
    }
    
    // Process successful result
    processDepGraph(result.DepGraph)
}
```

## Adding a New Plugin

To add support for a new ecosystem:

1. **Create package directory**:
   ```
   pkg/ecosystems/<ecosystem>/<tool>/
   ```

2. **Implement the interface**:
   ```go
   package tool
   
   import (
       "context"
       "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
       "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
   )
   
   type Plugin struct {
       // Plugin-specific fields
   }
   
   var _ ecosystems.SCAPlugin = (*Plugin)(nil)
   
   func (p *Plugin) BuildDepGraphsFromDir(
       ctx context.Context,
       log logger.Logger,
       dir string,
       options *ecosystems.SCAPluginOptions,
   ) (*ecosystems.PluginResult, error) {
       // 1. Discover manifest files in dir
       // 2. Resolve dependencies using ecosystem tooling
       // 3. Build depgraph.DepGraph using the builder
       // 4. Return PluginResult with results and processed files
   }
   ```

3. **Add ecosystem-specific options** (if needed):
   ```go
   // In options.go
   type MyEcosystemOptions struct {
       SpecificOption string
   }
   
   type SCAPluginOptions struct {
       Global      GlobalOptions
       Python      *PythonOptions
       MyEcosystem *MyEcosystemOptions  // Add here
   }
   ```

4. **Write tests**:
   ```go
   func TestPlugin_BuildDepGraphsFromDir(t *testing.T) {
       plugin := &Plugin{}
       options := ecosystems.NewPluginOptions()
       
       result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "./testdata", options)
       assert.NoError(t, err)
       assert.Len(t, result.Results, 1)
       assert.NotNil(t, result.Results[0].DepGraph)
       assert.Equal(t, "mymanager", result.Results[0].DepGraph.PkgManager.Name)
   }
   ```

## Design Principles

1. **Single Responsibility**: Each plugin focuses only on its ecosystem
2. **Dependency Inversion**: Depend on abstractions (interfaces), not concrete implementations
3. **Open/Closed**: Open for extension (new plugins), closed for modification (core interface)
4. **Interface Segregation**: Keep interfaces minimal and focused
5. **Don't Repeat Yourself**: Common functionality should be extracted to shared utilities

## References

- [Interface definition](./plugin_interface.go)
- [Configuration options](./options.go)
- [Python plugins](./python/)
- [Snyk dep-graph package](https://github.com/snyk/dep-graph)
