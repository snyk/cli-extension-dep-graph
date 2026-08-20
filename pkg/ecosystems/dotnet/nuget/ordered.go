package nuget

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// orderedMap is a JSON object decoded with its key order preserved.
//
// Document order is load-bearing in three places, all inherited from
// snyk-nuget-plugin, where these are JavaScript objects with insertion order:
// the positional fallback when mapping a framework to a `targets` key; which of
// two case-differing package keys wins; and the order siblings are walked in,
// which decides what gets pruned.
//
// Go map iteration is randomized, so plain maps would make the graph vary
// between runs of the same binary.
type orderedMap[V any] struct {
	keys   []string
	values map[string]V
}

var _ json.Unmarshaler = (*orderedMap[string])(nil)

// UnmarshalJSON decodes a JSON object, recording its key order. A JSON null
// decodes to an empty map, as an absent field would.
func (o *orderedMap[V]) UnmarshalJSON(data []byte) error {
	o.keys = nil
	o.values = nil

	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("reading object: %w", err)
	}

	if tok == nil {
		return nil
	}

	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected a JSON object, got %v", tok)
	}

	o.values = make(map[string]V)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("reading object key: %w", err)
		}

		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected a string object key, got %v", keyTok)
		}

		var value V
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("decoding value for key %q: %w", key, err)
		}

		// A duplicate key keeps its original position, as a JS object would.
		if _, exists := o.values[key]; !exists {
			o.keys = append(o.keys, key)
		}

		o.values[key] = value
	}

	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("reading object terminator: %w", err)
	}

	return nil
}

// Keys returns the keys in the order they appeared in the source document.
func (o *orderedMap[V]) Keys() []string {
	return o.keys
}

// Len reports how many keys the object had.
func (o *orderedMap[V]) Len() int {
	return len(o.keys)
}

// Get looks up a key.
func (o *orderedMap[V]) Get(key string) (V, bool) {
	value, ok := o.values[key]
	return value, ok
}
