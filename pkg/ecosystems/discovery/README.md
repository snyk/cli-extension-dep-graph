# File Discovery Package

Efficient file discovery utilities for finding manifest and configuration files in directory trees.

## Features

- **Multiple Target Files**: Find specific files by path
- **Multiple Glob Patterns**: Find files matching any of multiple patterns (e.g., `*.py`, `*.toml`)
- **Flexible Combination**: Use both target files and glob patterns together
- **Automatic Deduplication**: Returns unique results when multiple criteria match the same file
- **Exclude Patterns**: Skip directories and files using glob patterns
- **Context Support**: Cancellable operations for long-running searches
- **Efficient Traversal**: Uses `filepath.WalkDir` for optimal performance
- **Structured Logging**: `slog` integration for debugging

## Usage

The package uses the functional options pattern for clean and idiomatic configuration.

### Find a Specific File

```go
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithTargetFile("requirements.txt"))
```

### Find Multiple Specific Files

```go
// Multiple individual options
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithTargetFile("requirements.txt"),
    discovery.WithTargetFile("setup.py"),
    discovery.WithTargetFile("pyproject.toml"))

// Or use variadic form
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithTargetFiles("requirements.txt", "setup.py", "pyproject.toml"))
```

### Find Files Matching Pattern

```go
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithInclude("requirements*.txt"))
```

### Find Files Matching Multiple Patterns

```go
// Multiple individual patterns
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithInclude("*.py"),
    discovery.WithInclude("*.toml"),
    discovery.WithInclude("*.yml"))

// Or use variadic form
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithIncludes("*.py", "*.toml", "*.yml"))
```

### Combine Target Files and Globs

```go
// Find specific files AND all files matching patterns
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithTargetFile("requirements.txt"),
    discovery.WithInclude("*.py"),
    discovery.WithInclude("*.toml"))
// Returns: requirements.txt + all .py files + all .toml files (deduplicated)
```

### Exclude Patterns

```go
// Single exclude pattern
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithInclude("requirements.txt"),
    discovery.WithExclude("node_modules")) // Excludes node_modules directory
```

### Multiple Exclude Patterns

```go
// Multiple individual exclude patterns
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithInclude("*.py"),
    discovery.WithExclude("node_modules"),
    discovery.WithExclude(".*"),              // Exclude hidden directories
    discovery.WithExclude("__pycache__"))

// Or use variadic form
results, err := discovery.FindFiles(ctx, "/path/to/project",
    discovery.WithInclude("*.py"),
    discovery.WithExcludes("node_modules", ".*", "__pycache__"))
```

### Common Exclude Patterns

```go
// Exclude hidden directories
WithExclude(".*")

// Exclude specific directory
WithExclude("node_modules")

// Exclude file type
WithExclude("*.tmp")

// Exclude multiple patterns at once
WithExcludes("node_modules", ".*", "__pycache__", "*.pyc")
```

## Performance

- Uses `filepath.WalkDir` instead of `filepath.Walk` for better performance
- Skips entire directory trees when excluded
- Minimal allocations for large directory structures
- Context cancellation for early termination

## Return Value

Returns `[]FindResult` where each result contains:
- `Path`: Absolute path to the file
- `RelPath`: Relative path from the root directory

## Error Handling

- Returns error for invalid patterns or inaccessible root directory
- Logs warnings for inaccessible files/directories but continues walking
- Returns `context.Canceled` if operation is cancelled

## Examples

### Find Python Manifest Files

```go
ctx := context.Background()

// Find all Python manifest files
results, err := discovery.FindFiles(ctx, projectDir,
    discovery.WithTargetFile("requirements.txt"),      // Exact file
    discovery.WithIncludes("requirements*.txt", "*.toml", "setup.py"), // Patterns
    discovery.WithExcludes(".venv", "__pycache__", "*.pyc")) // Exclude virtual env and build artifacts

if err != nil {
    return err
}

for _, result := range results {
    fmt.Printf("Found: %s (at %s)\n", result.RelPath, result.Path)
}
```

### Find Configuration Files Across Ecosystem

```go
// Find manifest files for multiple package managers
results, err := discovery.FindFiles(ctx, projectDir,
    discovery.WithTargetFiles("package.json", "go.mod", "Gemfile", "pom.xml"),
    discovery.WithIncludes("*.csproj", "*.gradle", "*.toml"))
```
