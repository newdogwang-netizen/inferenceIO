package ingest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
)

type testTarEntry struct {
	name string
	body []byte
}

func TestStageImportArchiveStreamsTarAndGzip(t *testing.T) {
	event := testImportEvent("run-1", "run-1#0001", 1)
	eventLine, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	eventLine = append(eventLine, '\n')
	blobBody := []byte("blob contents")
	digest := protocol.SHA256Hex(blobBody)
	entries := []testTarEntry{
		{name: "run-1/events.jsonl", body: eventLine},
		{name: "run-1/manifest.json", body: []byte(`{"run_id":"run-1","recording_id":"run-1#0001","final_seq":1}`)},
		{name: "run-1/blobs/sha256-" + digest, body: blobBody},
	}

	for _, compressed := range []bool{false, true} {
		name := "tar"
		if compressed {
			name = "tar.gz"
		}
		t.Run(name, func(t *testing.T) {
			stageDir := t.TempDir()
			if err := os.Chmod(stageDir, 0o700); err != nil {
				t.Fatal(err)
			}
			staged, err := stageImportArchive(bytes.NewReader(makeTar(t, entries, compressed)), stageDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(staged.blobs) != 1 || staged.blobs[0].sha256 != digest {
				t.Fatalf("unexpected staged import: %+v", staged)
			}
			assertPrivateFile(t, staged.eventsPath, eventLine)
			assertPrivateFile(t, staged.blobs[0].path, blobBody)
			_, recordingID, err := importManifestHints(staged.manifest)
			if err != nil {
				t.Fatal(err)
			}
			summary, err := validateImportEvents(staged.eventsPath, recordingID)
			if err != nil {
				t.Fatal(err)
			}
			if summary.recordingID != event.RecordingID || summary.runID != event.RunID || summary.events != 1 || summary.lastSeq != 1 {
				t.Fatalf("unexpected event summary: %+v", summary)
			}
		})
	}
}

func TestImportRunDirUsesTheNormalDurabilityPath(t *testing.T) {
	db := testDB(t)
	objectRoot := t.TempDir()
	objects, err := objstore.NewFS(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: objects}
	principal := testPrincipal(t, db)
	principal.Kind = auth.KindUser
	principal.Role = auth.RoleOperator
	runID := "run-import-" + uuid.NewString()[:8]
	blobBody := []byte("imported blob")
	digest := protocol.SHA256Hex(blobBody)
	events := []protocol.Event{
		testImportEvent(runID, "", 1),
		testImportEvent(runID, "", 2),
		testImportEvent(runID, "", 3),
	}
	events[1].Payload = nil
	events[1].PayloadRef = &protocol.PayloadRef{SHA256: "sha256:" + digest, Size: int64(len(blobBody)), MediaType: "text/plain"}
	var eventLines bytes.Buffer
	for _, event := range events {
		eventLines.Write(mustJSON(t, event))
		eventLines.WriteByte('\n')
	}
	manifest := []byte(`{"run_id":"` + runID + `","status":"finished"}`)
	archive := makeTar(t, []testTarEntry{
		{name: runID + "/events.jsonl", body: eventLines.Bytes()},
		{name: runID + "/manifest.json", body: manifest},
		{name: runID + "/blobs/sha256-" + digest, body: blobBody},
	}, true)

	result, err := service.ImportRunDir(context.Background(), principal, bytes.NewReader(archive), 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.RecordingID != runID+"#0000" || result.CaptureRun != runID || result.Events != 3 || result.Batches != 2 || result.Blobs != 1 || result.DurableSeq != 3 || !result.Sealed {
		t.Fatalf("unexpected import result: %+v", result)
	}
	var durable int64
	var state, origin string
	if err := db.Pool.QueryRow(context.Background(), `select durable_seq, state, origin from recordings where id=$1`, result.RecordingID).Scan(&durable, &state, &origin); err != nil {
		t.Fatal(err)
	}
	if durable != 3 || state != "sealed" || origin != "import" {
		t.Fatalf("unexpected recording state: durable=%d state=%s origin=%s", durable, state, origin)
	}
}

func TestStageImportArchiveRejectsUnsafeAndDuplicateEntries(t *testing.T) {
	validEvents := []byte(string(mustJSON(t, testImportEvent("run", "rec", 1))) + "\n")
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		entries []testTarEntry
		code    string
	}{
		{name: "parent traversal", entries: []testTarEntry{{name: "../events.jsonl", body: validEvents}}, code: "malformed_request"},
		{name: "embedded traversal", entries: []testTarEntry{{name: "root/../events.jsonl", body: validEvents}}, code: "malformed_request"},
		{name: "absolute path", entries: []testTarEntry{{name: "/events.jsonl", body: validEvents}}, code: "malformed_request"},
		{name: "duplicate events", entries: []testTarEntry{{name: "events.jsonl", body: validEvents}, {name: "root/events.jsonl", body: validEvents}}, code: "malformed_request"},
		{name: "duplicate empty manifest", entries: []testTarEntry{{name: "events.jsonl", body: validEvents}, {name: "manifest.json"}, {name: "root/manifest.json"}}, code: "malformed_request"},
		{name: "invalid blob digest", entries: []testTarEntry{{name: "events.jsonl", body: validEvents}, {name: "blobs/sha256-not-a-digest", body: []byte("x")}}, code: "malformed_request"},
		{name: "duplicate blob", entries: []testTarEntry{{name: "events.jsonl", body: validEvents}, {name: "blobs/sha256-" + digest}, {name: "root/blobs/sha256-" + digest}}, code: "malformed_request"},
		{name: "missing events", entries: []testTarEntry{{name: "manifest.json", body: []byte(`{}`)}}, code: "malformed_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := stageImportArchive(bytes.NewReader(makeTar(t, tc.entries, false)), t.TempDir())
			if got := importErrorCode(err); got != tc.code {
				t.Fatalf("expected %s, got %q (%v)", tc.code, got, err)
			}
		})
	}
}

func TestValidateImportEventsRequiresOneContiguousRecording(t *testing.T) {
	tests := []struct {
		name   string
		events []protocol.Event
	}{
		{name: "starts at two", events: []protocol.Event{testImportEvent("run", "rec", 2)}},
		{name: "sequence gap", events: []protocol.Event{testImportEvent("run", "rec", 1), testImportEvent("run", "rec", 3)}},
		{name: "mixed run", events: []protocol.Event{testImportEvent("run-a", "rec", 1), testImportEvent("run-b", "rec", 2)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			for _, event := range tc.events {
				body.Write(mustJSON(t, event))
				body.WriteByte('\n')
			}
			file := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(file, body.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := validateImportEvents(file, ""); importErrorCode(err) != "malformed_request" {
				t.Fatalf("expected malformed_request, got %v", err)
			}
		})
	}
}

func TestHardLimitReaderRejectsTheFirstExcessByte(t *testing.T) {
	reader := &hardLimitReader{reader: strings.NewReader("abcdef"), remaining: 5}
	data, err := io.ReadAll(reader)
	if !errors.Is(err, errImportLimit) {
		t.Fatalf("expected import limit, got data=%q err=%v", data, err)
	}
	if string(data) != "abcde" {
		t.Fatalf("unexpected bounded data %q", data)
	}
}

func TestStageTarFileRejectsDeclaredOversizeBeforeCreatingFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "oversized")
	err := stageTarFile(strings.NewReader(""), MaxImportEventBytes+1, MaxImportEventBytes, destination)
	if importErrorCode(err) != "payload_too_large" {
		t.Fatalf("expected payload_too_large, got %v", err)
	}
	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("oversized entry created a staging file: %v", statErr)
	}
}

func testImportEvent(runID, recordingID string, seq int64) protocol.Event {
	return protocol.Event{
		SchemaVersion: 1,
		EventID:       uuid.Must(uuid.NewV7()).String(),
		RunID:         runID,
		RecordingID:   recordingID,
		Seq:           seq,
		MonotonicNS:   seq,
		WallTime:      time.Unix(1_700_000_000+seq, 0).UTC(),
		Source:        protocol.SourceProxy,
		Event:         protocol.EvSSEChunk,
		Payload:       json.RawMessage(`{"data":"ok"}`),
		Redaction:     &protocol.Redaction{Policy: "default"},
	}
}

func makeTar(t *testing.T, entries []testTarEntry, compressed bool) []byte {
	t.Helper()
	var output bytes.Buffer
	var destination io.Writer = &output
	var gz *gzip.Writer
	if compressed {
		gz = gzip.NewWriter(&output)
		destination = gz
	}
	tw := tar.NewWriter(destination)
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertPrivateFile(t *testing.T, path string, want []byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("staged file %s mode is %o, want 600", path, info.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("staged file %s mismatch", path)
	}
}

func importErrorCode(err error) string {
	var apiError *httpapi.APIError
	if errors.As(err, &apiError) {
		return apiError.Code
	}
	return ""
}
