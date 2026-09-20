package pipeline

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPostgresJSONReplacesNULWithoutChangingNumbers(t *testing.T) {
	raw := json.RawMessage(`{"text":"before\u0000after","nested":["ok\u0000",9007199254740993],"literal":"\\u0000"}`)
	clean, replacements, err := postgresJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if replacements != 2 {
		t.Fatalf("replacements=%d JSON=%s", replacements, clean)
	}
	if strings.ContainsRune(string(clean), '\x00') {
		t.Fatalf("PostgreSQL-unsafe NUL survived: %s", clean)
	}
	var decoded map[string]any
	dec := json.NewDecoder(strings.NewReader(string(clean)))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["text"] != "before\ufffdafter" || decoded["literal"] != `\u0000` {
		t.Fatalf("unexpected strings: %#v", decoded)
	}
	nested := decoded["nested"].([]any)
	if nested[1].(json.Number).String() != "9007199254740993" {
		t.Fatalf("number changed: %#v", nested[1])
	}
}

func TestPostgresJSONRejectsNULKeyCollision(t *testing.T) {
	_, _, err := postgresJSON(json.RawMessage(`{"a\u0000":1,"a\ufffd":2}`))
	if err == nil {
		t.Fatal("expected key-collision error")
	}
}
