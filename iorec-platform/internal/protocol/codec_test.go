package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sampleEvents(rec string, from, n int64) []Event {
	var evs []Event
	for i := int64(0); i < n; i++ {
		evs = append(evs, Event{
			SchemaVersion: 1, EventID: uuid.Must(uuid.NewV7()).String(), RunID: "run1", RecordingID: rec, Seq: from + i,
			MonotonicNS: 1000 * (from + i), WallTime: time.Unix(1700000000+from+i, 0).UTC(),
			Source: SourceProxy, Event: EvSSEChunk,
			IDs:       IDs{AttemptID: "a1", ConnectionID: "c1", PID: 42},
			Payload:   json.RawMessage(`{"data":"hello"}`),
			Redaction: &Redaction{Policy: "default"},
		})
	}
	return evs
}

func TestRustRecorderEnvelopeFixtureIsTheWireContract(t *testing.T) {
	line, err := os.ReadFile("testdata/rust-event-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	event, err := DecodeEvent(bytes.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	if event.Seq != 1 || event.IDs.TaskID != "task-1" || event.IDs.AgentSessionID != "session-1" || event.IDs.ParentSpanID != "parent-1" || event.PayloadRef == nil || event.PayloadRef.SHA256[:7] != "sha256:" {
		t.Fatalf("recorder envelope decoded incorrectly: %+v", event)
	}
	event.RecordingID = "run-cross-language#0000"
	header, compressed, err := EncodeBatch([]Event{event}, []BlobRef{{SHA256: event.PayloadRef.SHA256[7:], Size: event.PayloadRef.Size}})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := WriteBatchBody(&body, header, compressed); err != nil {
		t.Fatal(err)
	}
	decodedHeader, _, raw, err := ReadBatchBody(&body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseEvents(decodedHeader, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].RecordingID != event.RecordingID || decoded[0].EventID != event.EventID {
		t.Fatalf("recorder batch round trip failed: %+v", decoded)
	}
}

func TestPublishedSchemasMatchEmbeddedCopies(t *testing.T) {
	for _, name := range []string{SchemaEventV1, SchemaBatchV1, SchemaCapabilitiesV1} {
		published, err := os.ReadFile("../../schemas/" + name)
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := schemaFS.ReadFile("schemas/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(published, embedded) {
			t.Fatalf("published and embedded %s differ", name)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	evs := sampleEvents("run1#0001", 120, 39)
	hdr, comp, err := EncodeBatch(evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.BatchID != "run1#0001:000000000120-000000000158" || hdr.EventCount != 39 {
		t.Fatalf("bad header %+v", hdr)
	}
	var body bytes.Buffer
	if err := WriteBatchBody(&body, hdr, comp); err != nil {
		t.Fatal(err)
	}
	h2, _, raw, err := ReadBatchBody(&body)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHeaderRange(h2); err != nil {
		t.Fatal(err)
	}
	got, err := ParseEvents(h2, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 39 || got[0].Seq != 120 || got[38].Seq != 158 || got[5].IDs.PID != 42 {
		t.Fatalf("bad events")
	}
}

func TestHashMismatch(t *testing.T) {
	evs := sampleEvents("r", 1, 3)
	hdr, comp, _ := EncodeBatch(evs, nil)
	hdr.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	var body bytes.Buffer
	_ = WriteBatchBody(&body, hdr, comp)
	_, _, _, err := ReadBatchBody(&body)
	de, ok := err.(*DecodeError)
	if !ok || de.Code != "hash_mismatch" {
		t.Fatalf("expected hash_mismatch, got %v", err)
	}
}

func TestSeqDiscontinuityRejected(t *testing.T) {
	evs := sampleEvents("r", 1, 3)
	evs[2].Seq = 5
	if _, _, err := EncodeBatch(evs, nil); err == nil {
		t.Fatal("expected encode error")
	}
}

func TestSchemaRejectsMissingRedaction(t *testing.T) {
	evs := sampleEvents("r", 1, 1)
	evs[0].Redaction = nil
	if _, _, err := EncodeBatch(evs, nil); err == nil {
		t.Fatal("expected schema error")
	}
}

func TestReadBatchBodyBoundsHeaderAndDeclaredZstdOutput(t *testing.T) {
	oversizedHeader := append(bytes.Repeat([]byte("x"), MaxBatchHeaderBytes+1), '\n')
	if _, _, _, err := ReadBatchBody(bytes.NewReader(oversizedHeader)); decodeCode(err) != "payload_too_large" {
		t.Fatalf("expected bounded header rejection, got %v", err)
	}

	evs := sampleEvents("r", 1, 1)
	hdr, comp, err := EncodeBatch(evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The compressed stream expands beyond the attacker's declared size. The
	// decoder must honor the declared cap instead of allocating the real output.
	hdr.ByteLength = 1
	var body bytes.Buffer
	if err := WriteBatchBody(&body, hdr, comp); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ReadBatchBody(&body); decodeCode(err) != "payload_too_large" {
		t.Fatalf("expected zstd expansion rejection, got %v", err)
	}
}

func TestReadBatchHeaderValidatesWithoutDecodingPayload(t *testing.T) {
	events := sampleEvents("header-only#0000", 1, 1)
	header, compressed, err := EncodeBatch(events, []BlobRef{{SHA256: SHA256Hex([]byte("blob")), Size: 4}})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := WriteBatchBody(&body, header, compressed); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadBatchHeader(&body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.BatchID != header.BatchID || decoded.RecordingID != header.RecordingID || len(decoded.Blobs) != 1 || decoded.Blobs[0].SHA256 != header.Blobs[0].SHA256 {
		t.Fatalf("header-only decode changed identity: got=%+v want=%+v", decoded, header)
	}
	if _, err := ReadBatchHeader(bytes.NewReader([]byte(`{"batch_id":"missing-newline"}`))); decodeCode(err) != "malformed_batch" {
		t.Fatalf("missing header delimiter accepted: %v", err)
	}
	oversized := append(bytes.Repeat([]byte("x"), MaxBatchHeaderBytes+1), '\n')
	if _, err := ReadBatchHeader(bytes.NewReader(oversized)); decodeCode(err) != "payload_too_large" {
		t.Fatalf("oversized header accepted: %v", err)
	}
}

func TestParseEventsRejectsExcessiveJSONNesting(t *testing.T) {
	nested := bytes.Repeat([]byte("["), maxJSONDepth+1)
	nested = append(nested, '0')
	nested = append(nested, bytes.Repeat([]byte("]"), maxJSONDepth+1)...)
	nested = append(nested, '\n')
	hdr := BatchHeader{FirstSeq: 1, LastSeq: 1, EventCount: 1}
	if _, err := ParseEvents(hdr, nested); decodeCode(err) != "malformed_batch" {
		t.Fatalf("expected nesting rejection, got %v", err)
	}
}

func decodeCode(err error) string {
	if decoded, ok := err.(*DecodeError); ok {
		return decoded.Code
	}
	return ""
}
