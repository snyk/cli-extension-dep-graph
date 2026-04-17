package argparser

import (
	"encoding"
	"fmt"
	"reflect"
	"strings"
)

// Package argparser provides a reflection-based command-line argument parser that maps
// flags to struct fields using struct tags.
//
// HOW IT WORKS:
//
// 1. Tag-based mapping: Struct fields are annotated with `arg` tags that specify the
//    flag names they correspond to. Multiple flag names (including aliases) can be
//    specified as comma-separated values, e.g., `arg:"--flag,--alias,-f"`.
//
// 2. Reflection-based discovery: The parser uses Go's reflection API to introspect
//    the destination struct at runtime, building a map of flag names to field paths.
//    This allows it to handle nested and embedded structs automatically.
//
// 3. Field path navigation: Since structs can be nested or embedded, the parser stores
//    field paths as slices of indices ([]int). When a flag is encountered, the parser
//    navigates through the struct hierarchy using these indices to reach the target field.
//
// 4. Type-aware parsing: The parser handles different field types:
//    - bool: Presence of flag sets to true (no value required)
//    - string: Next argument is used as the value
//    - *string: Next argument is used to create a pointer to string
//    - []string: Collects all following non-flag arguments into a slice
//    - encoding.TextUnmarshaler: Delegates parsing to the type's UnmarshalText method
//
// 5. Unknown flag handling: Flags not found in the tag map are silently ignored,
//    along with their potential values. This allows the parser to be used in contexts
//    where multiple parsers handle different subsets of flags.
//
// EXAMPLE USAGE:
//
//   type Config struct {
//       Verbose bool     `arg:"--verbose,-v"`
//       Output  string   `arg:"--output,-o"`
//       Files   []string `arg:"--files,-f"`
//   }
//
//   var cfg Config
//   err := Parse([]string{"--verbose", "--output", "result.txt", "-f", "a.go", "b.go"}, &cfg)
//   // cfg.Verbose == true
//   // cfg.Output == "result.txt"
//   // cfg.Files == []string{"a.go", "b.go"}

const errRequiresValue = "%s requires a value"

// Parse parses command line flags into a struct using arg tags.
// Unknown flags are silently ignored.
func Parse(rawFlags []string, dest interface{}) error { //nolint:gocyclo // Complexity is acceptable for a parser function
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("dest must be a pointer to a struct")
	}

	v = v.Elem()

	// Build a map of flag names to field info
	flagMap := make(map[string]fieldInfo)
	buildFlagMap(v, []int{}, flagMap)

	// Parse the raw flags
	for i := 0; i < len(rawFlags); i++ {
		flag := rawFlags[i]
		var flagValue string
		var hasEqualsSyntax bool

		// Handle --flag=value syntax
		if strings.HasPrefix(flag, "-") && strings.Contains(flag, "=") {
			parts := strings.SplitN(flag, "=", 2)
			flag = parts[0]
			if len(parts) == 2 {
				flagValue = parts[1]
				hasEqualsSyntax = true
			}
		}

		info, known := flagMap[flag]
		if !known {
			// Unknown flag - skip it and potentially its value
			if !hasEqualsSyntax && strings.HasPrefix(flag, "-") && i+1 < len(rawFlags) && !strings.HasPrefix(rawFlags[i+1], "-") {
				i++ // Skip potential value
			}
			continue
		}

		// Navigate to the field using the path
		field := v
		for _, idx := range info.fieldPath {
			field = field.Field(idx)
		}

		// Check if the field implements encoding.TextUnmarshaler
		if field.CanAddr() && field.Addr().Type().Implements(reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()) {
			if err := handleTextUnmarshaler(field, flag, flagValue, hasEqualsSyntax, rawFlags, &i); err != nil {
				return err
			}
			continue
		}

		switch info.fieldType.Kind() {
		case reflect.Bool:
			field.SetBool(true)

		case reflect.String:
			var value string
			if hasEqualsSyntax {
				value = flagValue
			} else {
				if i+1 >= len(rawFlags) {
					return fmt.Errorf(errRequiresValue, flag)
				}
				i++
				value = rawFlags[i]
			}
			field.SetString(value)

		case reflect.Ptr:
			if info.fieldType.Elem().Kind() == reflect.String {
				var value string
				if hasEqualsSyntax {
					value = flagValue
				} else {
					if i+1 >= len(rawFlags) {
						return fmt.Errorf(errRequiresValue, flag)
					}
					i++
					value = rawFlags[i]
				}
				field.Set(reflect.ValueOf(&value))
			}

		case reflect.Slice:
			if info.fieldType.Elem().Kind() == reflect.String {
				// Collect all space-separated non-flag values
				values := []string{}
				if hasEqualsSyntax {
					// For equals syntax, only use the single value
					values = append(values, flagValue)
				} else {
					for i+1 < len(rawFlags) && !strings.HasPrefix(rawFlags[i+1], "-") {
						i++
						values = append(values, rawFlags[i])
					}
				}
				field.Set(reflect.ValueOf(values))
			}

		default:
			// Unsupported type, skip
		}
	}

	return nil
}

type fieldInfo struct {
	fieldPath []int
	fieldType reflect.Type
}

// handleTextUnmarshaler handles fields that implement encoding.TextUnmarshaler.
func handleTextUnmarshaler(field reflect.Value, flag, flagValue string, hasEqualsSyntax bool, rawFlags []string, i *int) error {
	var value string
	if hasEqualsSyntax {
		value = flagValue
	} else {
		if *i+1 >= len(rawFlags) {
			return fmt.Errorf(errRequiresValue, flag)
		}
		*i++
		value = rawFlags[*i]
	}
	unmarshaler, ok := field.Addr().Interface().(encoding.TextUnmarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalText([]byte(value)); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", flag, err)
	}
	return nil
}

// buildFlagMap recursively builds a map of flag names to field paths, handling embedded structs.
func buildFlagMap(v reflect.Value, path []int, flagMap map[string]fieldInfo) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		currentPath := append([]int{}, path...)
		currentPath = append(currentPath, i)

		// Handle embedded structs
		if field.Anonymous && field.Type.Kind() == reflect.Struct {
			buildFlagMap(v.Field(i), currentPath, flagMap)
			continue
		}

		tag := field.Tag.Get("arg")
		if tag == "" {
			continue
		}

		info := fieldInfo{
			fieldPath: currentPath,
			fieldType: field.Type,
		}

		// Parse tag: "--flag,--alias,-f"
		parts := strings.Split(tag, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				flagMap[part] = info
			}
		}
	}
}
