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
type ScaPlugin interface {
    BuildDepGraphsFromDir(ctx context.Context, dir string, options *ScaPluginOptions) ([]ScaResult, error)
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
// This line ensures Plugin implements ScaPlugin at compile time
var _ ecosystems.ScaPlugin = (*Plugin)(nil)
```
If the interface isn't properly implemented, the code won't compile—catching errors early.

#### 2. **Implicit Implementation**
Unlike explicit interface implementation in other languages, Go interfaces are satisfied implicitly. Any type that implements the required methods automatically implements the interface, making it easy to create plugins without tight coupling.

#### 3. **Dependency Injection**
```go
func AnalyzeDependencies(plugin ScaPlugin, dir string) error {
    results, err := plugin.BuildDepGraphsFromDir(context.Background(), dir, options)
    // ...
}
```
Functions can accept any type that implements `ScaPlugin`, enabling easy testing with mock implementations and swapping between different ecosystem plugins.

#### 4. **Composition Over Inheritance**
Go's interfaces encourage composition. You can embed interfaces or compose structs to build complex behavior from simple primitives, avoiding deep inheritance hierarchies.

#### 5. **Zero Overhead Abstraction**
Interface calls in Go are optimized by the compiler and have minimal runtime overhead, making abstraction essentially free from a performance perspective.

## Data Structures

### Depgraph: Adjacency List Representation

The dependency graph uses an **adjacency list** structure rather than a nested tree:

```go
type Depgraph struct {
    Packages      map[PackageID]Package     `json:"packages"`
    Graph         map[PackageID][]PackageID `json:"graph"`
    RootPackageID PackageID                 `json:"rootPackageId"`
}
```

#### Why Adjacency List?

**Advantages:**
- ✅ **No Duplication**: Shared dependencies appear once in memory
- ✅ **Efficient Queries**: O(n) to find all packages that depend on X
- ✅ **Cycle Detection**: Standard graph algorithms work naturally
- ✅ **Memory Efficient**: Large graphs with many shared dependencies use less memory
- ✅ **Standard Format**: Compatible with graph analysis tools and algorithms

**Example:**
```go
depgraph := Depgraph{
    Packages: map[PackageID]Package{
        "app@1.0.0":  {PackageID: "app@1.0.0", PackageName: "app", Version: "1.0.0"},
        "libA@2.0.0": {PackageID: "libA@2.0.0", PackageName: "libA", Version: "2.0.0"},
        "libB@3.0.0": {PackageID: "libB@3.0.0", PackageName: "libB", Version: "3.0.0"},
        "shared@1.5.0": {PackageID: "shared@1.5.0", PackageName: "shared", Version: "1.5.0"},
    },
    Graph: map[PackageID][]PackageID{
        "app@1.0.0":    {"libA@2.0.0", "libB@3.0.0"},
        "libA@2.0.0":   {"shared@1.5.0"},
        "libB@3.0.0":   {"shared@1.5.0"}, // shared dependency appears only once in Packages
        "shared@1.5.0": {},
    },
    RootPackageID: "app@1.0.0",
}
```

### ScaResult: Analysis Output

```go
type ScaResult struct {
    DepGraph Depgraph `json:"depGraph"`
    Metadata Metadata `json:"metadata"`
}
```

Each result contains:
- **DepGraph**: The complete dependency graph
- **Metadata**: Context about the analysis (target file, runtime environment)

Plugins return `[]ScaResult` to support:
- Monorepos with multiple projects
- Projects with multiple dependency graphs (e.g., runtime + dev dependencies)
- Workspaces (npm, yarn, cargo)

## Plugin Implementations

Plugins are organized by ecosystem:

```
pkg/ecosystems/
├── plugin_interface.go    # Core interface definition
├── options.go             # Configuration types
└── python/
    ├── pip/
    │   └── plugin.go      # Pip plugin implementation
    └── uv/
        └── plugin.go      # UV plugin implementation
```

### Current Plugins

#### Python Ecosystem

- **pip**: Discovers dependencies from `requirements.txt`
- **uv**: Modern Python package manager and resolver

### Future Ecosystems

The architecture supports adding plugins for:
- **JavaScript/TypeScript**: npm, yarn, pnpm
- **Java**: Maven, Gradle
- **.NET**: NuGet
- **Go**: Go modules

## Configuration

### ScaPluginOptions

```go
type ScaPluginOptions struct {
    Global GlobalOptions    // Options for all plugins
    Python *PythonOptions   // Python-specific options
}
```

Options support:
- **Global settings**: Apply to all ecosystems (e.g., `AllSubProjects`, `TargetFile`)
- **Ecosystem-specific settings**: Only relevant to particular package managers

### Builder Pattern

```go
options := ecosystems.NewPluginOptions().
    WithTargetFile("requirements.txt").
    WithAllSubProjects(true)

results, err := plugin.BuildDepGraphsFromDir(ctx, "/path/to/project", options)
```

## Usage Examples

### Basic Usage

```go
import (
    "context"
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
        fmt.Printf("Target: %s\n", result.Metadata.TargetFile)
        fmt.Printf("Root Package: %s\n", result.DepGraph.RootPackageID)
        fmt.Printf("Total Packages: %d\n", len(result.DepGraph.Packages))
    }
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
   )
   
   type Plugin struct {
       // Plugin-specific fields
   }
   
   var _ ecosystems.ScaPlugin = (*Plugin)(nil)
   
   func (p *Plugin) BuildDepGraphsFromDir(ctx context.Context, dir string, options *ecosystems.ScaPluginOptions) ([]ecosystems.ScaResult, error) {
       // 1. Discover manifest files in dir
       // 2. Resolve dependencies using ecosystem tooling
       // 3. Build Depgraph from resolved dependencies
       // 4. Return ScaResult with metadata
   }
   ```

3. **Add ecosystem-specific options** (if needed):
   ```go
   // In options.go
   type MyEcosystemOptions struct {
       SpecificOption string
   }
   
   type ScaPluginOptions struct {
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
       // More assertions
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
- ✅ Efficient graph operations

### For External Consumers
- ✅ Well-defined interface to implement
- ✅ Standard dependency graph format
- ✅ Compatible with Snyk workflows
- ✅ No tight coupling to Snyk internals
- ✅ Extensible for custom ecosystems

## References

- [Interface definition](./plugin_interface.go)
- [Configuration options](./options.go)
- [Python plugins](./python/)
