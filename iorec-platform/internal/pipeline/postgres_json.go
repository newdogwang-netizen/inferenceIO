package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// postgresJSON returns a JSON value that PostgreSQL jsonb can represent.
// PostgreSQL rejects U+0000 even when it is validly escaped in JSON. The raw
// body remains content-addressed evidence; only the query projection replaces
// NUL with U+FFFD. Re-decoding also makes lone UTF-16 surrogates safe.
func postgresJSON(raw json.RawMessage) (json.RawMessage, int, error) {
	if len(raw) == 0 {
		return nil, 0, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, 0, fmt.Errorf("decode JSON projection: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, 0, fmt.Errorf("decode JSON projection: multiple values")
		}
		return nil, 0, fmt.Errorf("decode JSON projection trailer: %w", err)
	}
	value, replaced, err := replaceJSONNUL(value)
	if err != nil {
		return nil, 0, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, 0, fmt.Errorf("encode JSON projection: %w", err)
	}
	return encoded, replaced, nil
}

func replaceJSONNUL(value any) (any, int, error) {
	switch value := value.(type) {
	case string:
		clean, replaced := postgresText(value)
		return clean, replaced, nil
	case []any:
		total := 0
		for i := range value {
			clean, n, err := replaceJSONNUL(value[i])
			if err != nil {
				return nil, 0, err
			}
			value[i] = clean
			total += n
		}
		return value, total, nil
	case map[string]any:
		clean := make(map[string]any, len(value))
		origins := make(map[string]string, len(value))
		total := 0
		for key, child := range value {
			cleanKey, keyNUL := postgresText(key)
			if origin, exists := origins[cleanKey]; exists && origin != key {
				return nil, 0, fmt.Errorf("sanitize JSON projection: NUL replacement collides for object key")
			}
			cleanChild, childNUL, err := replaceJSONNUL(child)
			if err != nil {
				return nil, 0, err
			}
			clean[cleanKey] = cleanChild
			origins[cleanKey] = key
			total += keyNUL + childNUL
		}
		return clean, total, nil
	default:
		return value, 0, nil
	}
}

func postgresText(value string) (string, int) {
	count := strings.Count(value, "\x00")
	if count == 0 {
		return value, 0
	}
	return strings.ReplaceAll(value, "\x00", "\ufffd"), count
}
