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

```go
type SCAPlugin interface {
    BuildDepGraphsFromDir(ctx context.Context, dir string, options *SCAPluginOptions) ([]SCAResult, error)
}
```

Every plugin implements this interface to:
- **Discover** dependency manifests in a directory (e.g., `requirements.txt`, `package.json`)
- **Resolve** dependencies using the ecosystem's native tooling
- **Build** a standardized dependency graph representation
- **Return** results with metadata about the analysis

### Why Go Interfaces?

Go's interface design provides several benefits for plugin architecture:

#### 1. **Compile-Time Verification**
```go
// This line ensures Plugin implements SCAPlugin at compile time
var _ ecosystems.SCAPlugin = (*Plugin)(nil)
```
If the interface isn't properly implemented, the code won't compile—catching errors early.

#### 2. **Implicit Implementation**
Unlike explicit interface implementation in other languages, Go interfaces are satisfied implicitly. Any type that implements the required methods automatically implements the interface, making it easy to create plugins without tight coupling.

#### 3. **Dependency Injection**
```go
func AnalyzeDependencies(plugin SCAPlugin, dir string) error {
    results, err := plugin.BuildDepGraphsFromDir(context.Background(), dir, options)
    // ...
}
```
Functions can accept any type that implements `SCAPlugin`, enabling easy testing with mock implementations and swapping between different ecosystem plugins.

#### 4. **Composition Over Inheritance**
Go's interfaces encourage composition. You can embed interfaces or compose structs to build complex behavior from simple primitives, avoiding deep inheritance hierarchies.

#### 5. **Zero Overhead Abstraction**
Interface calls in Go are optimized by the compiler and have minimal runtime overhead, making abstraction essentially free from a performance perspective.

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

Plugins return `[]SCAResult` to support:
- Monorepos with multiple projects
- Projects with multiple dependency graphs (e.g., runtime + dev dependencies)
- Workspaces (npm, yarn, cargo)

## Configuration

### SCAPluginOptions

```go
type SCAPluginOptions struct {
    Global GlobalOptions    // Options that apply to all plugins
    Python *PythonOptions   // Python-specific options
}
```

### GlobalOptions

Options that apply across all ecosystem plugins:

```go
type GlobalOptions struct {
    TargetFile  *string  // Specific manifest file to analyze
    AllProjects bool     // Discover and analyze all projects in directory
}
```

| Option | Type | Description |
|--------|------|-------------|
| `TargetFile` | `*string` | Path to a specific manifest file to analyze. When set, only this file is processed. |
| `AllProjects` | `bool` | When `true`, recursively discovers and analyzes all supported manifest files in the directory. |

### PythonOptions

Python-specific options (currently empty, reserved for future use):

```go
type PythonOptions struct{}
```

### Builder Pattern

Use the fluent builder pattern to configure options:

```go
// Analyze a specific file
options := ecosystems.NewPluginOptions().
    WithTargetFile("requirements.txt")

// Analyze all projects in directory
options := ecosystems.NewPluginOptions().
    WithAllProjects(true)

// Default options (single project at root)
options := ecosystems.NewPluginOptions()
```

### Available Builder Methods

| Method | Description |
|--------|-------------|
| `NewPluginOptions()` | Creates a new options instance with defaults |
| `WithTargetFile(path string)` | Sets a specific manifest file to analyze |
| `WithAllProjects(bool)` | Enables/disables recursive project discovery |

## Plugin Implementations

Plugins are organized by ecosystem:

```
pkg/ecosystems/
├── plugin_interface.go    # Core interface definition
├── options.go             # Configuration types
├── discovery/             # File discovery utilities
└── python/
    ├── pip/
    │   └── plugin.go      # Pip plugin implementation
    └── uv/
        └── plugin.go      # UV plugin implementation
```

### Current Plugins

#### Python Ecosystem

- **pip**: Discovers dependencies from `requirements.txt` using `pip install --dry-run --report`
- **uv**: Modern Python package manager and resolver (in development)

### Future Ecosystems

The architecture supports adding plugins for:
- **JavaScript/TypeScript**: npm, yarn, pnpm
- **Java**: Maven, Gradle
- **.NET**: NuGet
- **Go**: Go modules

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
    
    results, err := plugin.BuildDepGraphsFromDir(
        context.Background(),
        "/path/to/python/project",
        options,
    )
    if err != nil {
        // Handle error
    }
    
    for _, result := range results {
        if result.Error != nil {
            fmt.Printf("Error analyzing %s: %v\n", result.Metadata.TargetFile, result.Error)
            continue
        }
        
        fmt.Printf("Target: %s\n", result.Metadata.TargetFile)
        fmt.Printf("Runtime: %s\n", result.Metadata.Runtime)
        fmt.Printf("Package Manager: %s\n", result.DepGraph.PkgManager.Name)
        fmt.Printf("Total Packages: %d\n", len(result.DepGraph.Pkgs))
    }
}
```

### Analyzing All Projects

```go
options := ecosystems.NewPluginOptions().
    WithAllProjects(true)

results, err := plugin.BuildDepGraphsFromDir(ctx, "/path/to/monorepo", options)
// Returns results for all requirements.txt files found
```

### Handling Errors in Results

```go
for _, result := range results {
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
       "github.com/snyk/dep-graph/go/pkg/depgraph"
   )
   
   type Plugin struct {
       // Plugin-specific fields
   }
   
   var _ ecosystems.SCAPlugin = (*Plugin)(nil)
   
   func (p *Plugin) BuildDepGraphsFromDir(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]ecosystems.SCAResult, error) {
       // 1. Discover manifest files in dir
       // 2. Resolve dependencies using ecosystem tooling
       // 3. Build depgraph.DepGraph using the builder
       // 4. Return SCAResult with metadata
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
       
       results, err := plugin.BuildDepGraphsFromDir(context.Background(), "./testdata", options)
       assert.NoError(t, err)
       assert.Len(t, results, 1)
       assert.NotNil(t, results[0].DepGraph)
       assert.Equal(t, "mymanager", results[0].DepGraph.PkgManager.Name)
   }
   ```

## Design Principles

1. **Single Responsibility**: Each plugin focuses only on its ecosystem
2. **Dependency Inversion**: Depend on abstractions (interfaces), not concrete implementations
3. **Open/Closed**: Open for extension (new plugins), closed for modification (core interface)
4. **Interface Segregation**: Keep interfaces minimal and focused
5. **Don't Repeat Yourself**: Common functionality should be extracted to shared utilities

## Benefits Summary

### For Internal Use
- ✅ Consistent API across all ecosystems
- ✅ Easy to add new package manager support
- ✅ Testable with dependency injection
- ✅ Type-safe with compile-time checks
- ✅ Standard Snyk dep-graph format

### For External Consumers
- ✅ Well-defined interface to implement
- ✅ Standard dependency graph format compatible with Snyk tools
- ✅ Compatible with Snyk workflows
- ✅ No tight coupling to Snyk internals
- ✅ Extensible for custom ecosystems

## References

- [Interface definition](./plugin_interface.go)
- [Configuration options](./options.go)
- [Python plugins](./python/)
- [Snyk dep-graph package](https://github.com/snyk/dep-graph)
