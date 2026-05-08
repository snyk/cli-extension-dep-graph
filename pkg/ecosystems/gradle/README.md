# Gradle Dependency Graph Resolver

## Overview

This package implements a Gradle dependency graph resolver for the Snyk CLI ecosystem. It extracts complete dependency trees from Gradle projects using Gradle's native ResolutionResult API, producing dependency graphs that can be analysed for vulnerabilities and licence compliance.

The resolver works by injecting a custom init script (`snyk-deps-init.gradle`) into Gradle builds, which programmatically walks the resolved dependency graph for each project and configuration, outputting newline-delimited JSON (NDJSON) that is then converted into Snyk's internal dependency graph format.

## Design Decisions & Known Issues

### Gradle Version Support

**Target: Gradle 6+**

We explicitly target Gradle 6 and later versions. Gradle 5 reached end-of-life in 2019, making it inappropriate for current security tooling. This allows us to:

- Rely on stable ResolutionResult APIs introduced in Gradle 4.4+ and refined through Gradle 5-6
- Use modern Gradle features for better performance and reliability
- Avoid maintaining compatibility with deprecated APIs

The embedded init script includes compatibility shims for API differences between Gradle 6-9, but does not support Gradle 5 or earlier.

### Configuration Handling Philosophy

**Non-prescriptivist approach**

This resolver deliberately avoids being prescriptive about which Gradle configurations are "relevant" to a project. Unlike traditional approaches that focus only on runtime dependencies, we recognise several important factors:

1. **Plugin ecosystem diversity**: Gradle plugins can introduce arbitrary configurations with different semantics
2. **Supply chain security**: Dependencies used during the build process (e.g., annotation processors, code generators, test frameworks) represent potential attack vectors and should be analysable
3. **Client flexibility**: Different clients may have legitimate reasons to focus on specific configurations

**Implementation**: Rather than hardcoding configuration filters, this responsibility is delegated to clients via:
- Support for `configuration-matching` patterns (planned)
- Gradle property pass-through (e.g., `-Pconfiguration=runtimeClasspath`)

This allows security tooling to make informed decisions about scope without the resolver making assumptions about what constitutes a "buildtime" vs "runtime" dependency.

### Graph Merging Trade-offs

**Current behaviour: Cross-configuration merging**

The resolver currently merges dependency graphs across all available configurations into a single unified graph. While this provides comprehensive visibility, it introduces a significant issue:

**Problem**: Dependencies may appear with multiple versions of the same transitive dependency when different configurations resolve to different versions, particularly when Gradle plugins don't properly respect platform dependencies declared by the project.

**Example scenario**:
```
compileClasspath    → guava:30.0
testRuntimeClasspath → guava:31.0  (due to test framework override)
```

This results in both versions appearing in the merged graph, potentially causing confusion in vulnerability analysis.

**Rationale for current approach**:
- Provides complete visibility into all dependencies actually used by the build
- Avoids the complexity of per-configuration filtering logic
- Defers configuration selection decisions to clients who understand their specific use cases

**Future considerations**: Per-configuration filtering will likely be added when feature parity work begins, allowing clients to request specific configuration scopes.

#### Edge deduplication and ordering

When the same `(parent, child)` edge is contributed by more than one configuration (for example a direct dependency that appears in `compileClasspath`, `runtimeClasspath`, `testCompileClasspath` and `testRuntimeClasspath`), the merged graph contains the edge **exactly once** rather than once per contributing configuration. The dep-graph schema treats each parent's `Deps` as a set of edges, so multi-edges would be schema violations and would inflate downstream vulnerable-path counts.

Configurations are walked in **Gradle's natural evaluation order**, preserving the sequence that Gradle itself uses during dependency resolution. When the same edge appears in multiple configurations, its position in the parent's `Deps` slice is taken from the first configuration in evaluation order that contributes it. This makes the merged graph deterministic across runs and across JDK / Gradle versions, and crucially means that cross-configuration edge ordering **is semantically meaningful** — it reflects Gradle's actual dependency processing sequence rather than arbitrary alphabetical sorting. This provides more accurate representation for clients that need declaration order semantics (for example, to surface the most relevant "nearest" path for a CVE), though `--configuration-matching` will still be valuable for configuration-specific analysis once that lands.

### Classifier Handling

**Current decision: Classifiers not captured**

The resolver currently does not capture or report Maven classifiers at all. Dependency IDs are created using only `group:artifact:version` format, ignoring any classifier information that may be present in the resolved dependencies.

**Rationale**:
- Upstream Snyk services don't currently make use of classifier information for vulnerability analysis
- Simplifies the dependency graph structure and processing logic
- Most security-relevant dependencies don't rely on classifiers for their primary functionality

**Implementation**: The init script extracts dependency IDs using `${group}:${name}:${version}` format only. Artifacts with classifiers (e.g., `commons-io:commons-io:2.6:sources`) are treated identically to their main artifacts, potentially causing different classifier variants to be merged in the dependency graph.

This limitation should be addressed if classifier-specific vulnerabilities become relevant or if upstream services begin requiring classifier information for accurate analysis.

## Technical Implementation Notes

### File and Project Discovery

**Build file discovery**

The resolver discovers Gradle projects by searching for build files and settings files in the target directory tree:
- `build.gradle` and `build.gradle.kts` (build files)
- `settings.gradle` and `settings.gradle.kts` (settings files)

When processing discovered files, the resolver prioritises build files over settings files for dependency extraction, since settings files don't contain dependency declarations.

**Multi-module project handling**

To avoid redundant work in multi-module projects, the resolver:

1. **Sorts discovered files** by path depth, then by resolved dependencies
2. **Tracks processed directories** using a map to avoid duplicate processing
3. **Handles subprojects efficiently** - when multiple build files exist in the same directory or when subprojects are discovered through root `settings.gradle` examination, the resolver ensures each project is processed only once

**TargetFile-specific processing**

When a specific `TargetFile` is requested:
- The resolver invokes the `:snykDependencyGraph` task on the root project
- The complete multi-module dependency output is generated
- Results are then **filtered to extract only the dependency graph** corresponding to the specified `TargetFile` project

This approach leverages Gradle's native multi-module handling whilst providing targeted results for individual project files.

### Memory Optimisation

The init script uses NDJSON output to handle large projects efficiently:
- Each subproject's dependencies are resolved and written by an isolated per-project task (`snykDependencyGraphProject`), then aggregated by the root `snykDependencyGraph` task
- One JSON object per line — no in-memory accumulation of the full document
- Suitable for projects with thousands of dependencies

### Execution Isolation

Gradle execution uses several flags for predictable, isolated behaviour:
- `--no-daemon`: Prevents state leakage between invocations

Parallel project execution is safe because each `snykDependencyGraphProject` task writes to its own output file — there is no shared mutable state between subproject tasks. Projects that opt in to parallel execution via `org.gradle.parallel=true` in their `gradle.properties` will have that setting respected.

`GRADLE_OPTS` configuration is left for invoking system to handle, following standard Gradle conventions rather than prescriptive memory tuning.

## Integration Tests

Real Gradle invocations are exercised by the integration suite under `pkg/ecosystems/gradle/plugin_integration_test.go`, gated behind the `integration,gradle` build tags. The fixtures live in `pkg/ecosystems/testdata/fixtures/gradle/`.

### Running locally

The tests need a working Gradle on `PATH` (or a wrapper inside the fixture). With those in place:

```sh
make test-gradle-integration
```

### Updating expected snapshots

Each fixture stores its expected `[]ecosystems.SCAResult` as `expected_plugin*.json`. After changing the plugin's output shape or adding a new fixture, regenerate the snapshots and inspect the diff before committing:

```sh
make update-gradle-fixtures
git diff pkg/ecosystems/testdata/fixtures/gradle/
```

This invokes the same suite with `UPDATE_FIXTURES=1`, which makes each test write the captured results back to disk instead of asserting.

### CI matrix

CircleCI runs the suite across `(gradle, jdk)` pairs `[(6, 11), (7, 17), (8, 21), (9, 25)]` whenever a PR touches files under `pkg/ecosystems/gradle/` or `pkg/ecosystems/testdata/fixtures/gradle/`. See `.circleci/continue-config.yml` for the job definition; each pair uses the official `gradle:<X>-jdk<Y>` Docker image.
