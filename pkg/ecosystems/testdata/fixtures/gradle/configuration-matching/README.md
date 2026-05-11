# Configuration Matching Test Fixture

This fixture tests the `--configuration-matching` flag functionality by using a Gradle project with dependencies spread across multiple configurations:

## Dependencies by Configuration

- **implementation**: `com.google.guava:guava:30.1.1-jre` (appears in runtime classpaths)
- **runtimeOnly**: `ch.qos.logback:logback-classic:1.2.12` (runtime classpaths only)
- **compileOnly**: `org.apache.commons:commons-lang3:3.14.0` (compile classpaths only) 
- **testImplementation**: `junit:junit:4.13.2`, `org.mockito:mockito-core:4.11.0` (test classpaths)
- **testRuntimeOnly**: `org.slf4j:slf4j-simple:1.7.36` (test runtime classpaths only)

## Test Cases

- **Full scan**: All dependencies from all configurations
- **Runtime only** (`(?i).*runtime.*`): implementation + runtimeOnly + testRuntimeOnly dependencies
- **Compile only** (`compile.*`): compileOnly + compileClasspath dependencies  
- **Test only** (`(?i)test.*`): testImplementation + testRuntimeOnly dependencies
- **Exact match** (`^runtimeClasspath$`): Only dependencies from the exact runtimeClasspath configuration

This validates that the regex filtering correctly includes/excludes configurations and their dependencies.