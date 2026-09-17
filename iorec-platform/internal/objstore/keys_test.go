package objstore

import (
	"strings"
	"testing"
)

func TestUntrustedIdentifiersAreSingleObjectKeySegments(t *testing.T) {
	prefix := RecordingPrefix("tenant", "project", "run/../../other#0000")
	if strings.Contains(prefix, "../") || !strings.Contains(prefix, "run%2F..%2F..%2Fother%230000") {
		t.Fatalf("recording identifier was not escaped: %s", prefix)
	}
	export := ExportKey("tenant", "project", "../../export", "../secret")
	if strings.Contains(export, "../") {
		t.Fatalf("export identifier was not escaped: %s", export)
	}
}
