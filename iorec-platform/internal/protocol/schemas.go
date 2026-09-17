// Package protocol implements the shared iorec event/batch wire protocol:
// envelope types, batch header, ndjson+zstd codec and JSON-Schema validation.
// It is intended to be imported by both the platform and the capture agent.
package protocol

import (
	"embed"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed all:schemas
var schemaFS embed.FS

// Schema names.
const (
	SchemaEventV1        = "event.v1.schema.json"
	SchemaBatchV1        = "batch.v1.schema.json"
	SchemaCapabilitiesV1 = "capabilities.v1.schema.json"
)

var compiled = map[string]*jsonschema.Schema{}

func init() {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, name := range []string{SchemaEventV1, SchemaBatchV1, SchemaCapabilitiesV1} {
		b, err := schemaFS.ReadFile("schemas/" + name)
		if err != nil {
			panic(fmt.Sprintf("protocol: missing embedded schema %s: %v", name, err))
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
		if err != nil {
			panic(fmt.Sprintf("protocol: bad schema %s: %v", name, err))
		}
		url := "https://iorec.dev/schemas/" + name
		if err := c.AddResource(url, doc); err != nil {
			panic(err)
		}
		s, err := c.Compile(url)
		if err != nil {
			panic(fmt.Sprintf("protocol: compile %s: %v", name, err))
		}
		compiled[name] = s
	}
}

// Validate checks a decoded JSON value (map[string]any / []any / primitives)
// against the named embedded schema.
func Validate(schema string, v any) error {
	s, ok := compiled[schema]
	if !ok {
		return fmt.Errorf("unknown schema %q", schema)
	}
	return s.Validate(v)
}
