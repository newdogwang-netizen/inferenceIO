package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/store"
)

// Integration tests need TEST_DATABASE_URL (a scratch PostgreSQL). They skip otherwise.
func testDB(t *testing.T) *store.DB {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func testPrincipal(t *testing.T, db *store.DB) auth.Principal {
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	return auth.Principal{Kind: auth.KindCollector, TenantID: tenant, ProjectID: project, Subject: "test"}
}

func events(rec string, from, n int64) []protocol.Event {
	var out []protocol.Event
	runID := rec
	if separator := strings.LastIndexByte(rec, '#'); separator >= 0 {
		runID = rec[:separator]
	}
	for i := int64(0); i < n; i++ {
		out = append(out, protocol.Event{SchemaVersion: 1, EventID: fmt.Sprintf("018bcfe5-6800-7000-8000-%012x", from+i), RunID: runID, RecordingID: rec, Seq: from + i, MonotonicNS: from + i, WallTime: time.Unix(1700000000+from+i, 0).UTC(), Source: protocol.SourceProxy, Event: protocol.EvSSEChunk, IDs: protocol.IDs{AttemptID: "a"}, Payload: json.RawMessage(`{"raw":"data: {}\n\n"}`), Redaction: &protocol.Redaction{Policy: "default"}})
	}
	return out
}

func boolPtr(value bool) *bool { return &value }

func TestRecordingSegmentsRequireSealedContiguousGlobalSequences(t *testing.T) {
	db := testDB(t)
	obj, _ := objstore.NewFS(t.TempDir())
	svc := &Service{DB: db, Obj: obj}
	p := testPrincipal(t, db)
	ctx := context.Background()
	run := "run-segments-" + uuid.NewString()[:8]
	first := run + "#0000"
	second := run + "#0001"
	third := run + "#0002"

	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: first, CaptureRunID: run, SegmentNo: 0, SequenceBase: 1, SchemaVersion: 1}); err == nil {
		t.Fatal("segment zero accepted a nonzero sequence base")
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: first, CaptureRunID: run, SegmentNo: 0, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UploadBatch(ctx, p, first, body(t, events(first, 1, 1))); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: third, CaptureRunID: run, SegmentNo: 2, SequenceBase: 1, SchemaVersion: 1}); err == nil {
		t.Fatal("segment two was created without segment one")
	} else if st, code := apiCode(err); st != 409 || code != "segment_predecessor_missing" {
		t.Fatalf("unexpected predecessor error: %v", err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: second, CaptureRunID: run, SegmentNo: 1, SequenceBase: 1, SchemaVersion: 1}); err == nil {
		t.Fatal("segment one was created before segment zero was sealed")
	} else if st, code := apiCode(err); st != 409 || code != "segment_sequence_conflict" {
		t.Fatalf("unexpected open predecessor error: %v", err)
	}
	if err := svc.Seal(ctx, p, first, SealRequest{FinalSeq: 1, RunFinal: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: second, CaptureRunID: run, SegmentNo: 1, SequenceBase: 2, SchemaVersion: 1}); err == nil {
		t.Fatal("segment one accepted a discontinuous sequence base")
	} else if st, code := apiCode(err); st != 409 || code != "segment_sequence_conflict" {
		t.Fatalf("unexpected sequence base error: %v", err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: second, CaptureRunID: run, SegmentNo: 1, SequenceBase: 1, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UploadBatch(ctx, p, second, body(t, events(second, 1, 1))); err == nil {
		t.Fatal("segment one accepted a batch at or below its sequence base")
	} else if st, code := apiCode(err); st != 400 || code != "malformed_batch" {
		t.Fatalf("unexpected sequence base batch error: %v", err)
	}
	result, err := svc.UploadBatch(ctx, p, second, body(t, events(second, 2, 1)))
	if err != nil || result.DurableSeq != 2 {
		t.Fatalf("segment one upload: result=%+v err=%v", result, err)
	}
	if err := svc.Seal(ctx, p, second, SealRequest{FinalSeq: 2, RunFinal: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UploadBatch(ctx, p, second, body(t, events(second, 3, 1))); err == nil {
		t.Fatal("sealed segment accepted evidence beyond final_seq")
	} else if st, code := apiCode(err); st != 409 || code != "final_seq_conflict" {
		t.Fatalf("unexpected sealed range error: %v", err)
	}
	var endedAt *time.Time
	if err := db.Pool.QueryRow(ctx, `select ended_at from capture_runs where id=$1`, run).Scan(&endedAt); err != nil || endedAt != nil {
		t.Fatalf("intermediate seal ended capture run: ended_at=%v err=%v", endedAt, err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: third, CaptureRunID: run, SegmentNo: 2, SequenceBase: 2, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	var durable, parsed int64
	if err := db.Pool.QueryRow(ctx, `select durable_seq, parsed_seq from recordings where id=$1`, third).Scan(&durable, &parsed); err != nil || durable != 2 || parsed != 2 {
		t.Fatalf("segment base was not initialized: durable=%d parsed=%d err=%v", durable, parsed, err)
	}
	manifest := json.RawMessage(`{"status":"finished"}`)
	if err := svc.Seal(ctx, p, second, SealRequest{FinalSeq: 2, Manifest: manifest, ManifestSHA256: protocol.SHA256Hex(manifest), RunFinal: boolPtr(true)}); err == nil {
		t.Fatal("a non-final segment finalized the capture run")
	} else if st, code := apiCode(err); st != 409 || code != "final_segment_conflict" {
		t.Fatalf("unexpected final segment error: %v", err)
	}
	if _, err := svc.UploadBatch(ctx, p, third, body(t, events(third, 3, 1))); err != nil {
		t.Fatal(err)
	}
	if err := svc.Seal(ctx, p, third, SealRequest{FinalSeq: 3, RunFinal: boolPtr(false)}); err != nil {
		t.Fatalf("intermediate final-segment seal: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `select ended_at from capture_runs where id=$1`, run).Scan(&endedAt); err != nil || endedAt != nil {
		t.Fatalf("intermediate final-segment seal ended capture run: ended_at=%v err=%v", endedAt, err)
	}
	if err := svc.Seal(ctx, p, third, SealRequest{FinalSeq: 3, Manifest: manifest, ManifestSHA256: protocol.SHA256Hex(manifest), RunFinal: boolPtr(true)}); err != nil {
		t.Fatalf("final segment promotion: %v", err)
	}
	var manifestSHA []byte
	if err := db.Pool.QueryRow(ctx, `select c.ended_at, r.manifest_sha256 from capture_runs c join recordings r on r.capture_run_id=c.id where c.id=$1 and r.id=$2`, run, third).Scan(&endedAt, &manifestSHA); err != nil || endedAt == nil || len(manifestSHA) != sha256.Size {
		t.Fatalf("final promotion was not persisted: ended_at=%v sha=%x err=%v", endedAt, manifestSHA, err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: run + "#0003", CaptureRunID: run, SegmentNo: 3, SequenceBase: 3, SchemaVersion: 1}); err == nil {
		t.Fatal("finalized capture run accepted another recording segment")
	} else if st, code := apiCode(err); st != 409 || code != "capture_run_finalized" {
		t.Fatalf("unexpected finalized run error: %v", err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: third, CaptureRunID: run, SegmentNo: 2, SequenceBase: 2, SchemaVersion: 1}); err != nil {
		t.Fatalf("idempotent declaration of final segment failed: %v", err)
	}
}

func body(t *testing.T, evs []protocol.Event) *bytes.Buffer {
	hdr, comp, err := protocol.EncodeBatch(evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := protocol.WriteBatchBody(&b, hdr, comp); err != nil {
		t.Fatal(err)
	}
	return &b
}

func apiCode(err error) (int, string) {
	var ae *httpapi.APIError
	if errors.As(err, &ae) {
		return ae.Status, ae.Code
	}
	return 0, ""
}

func TestBatchCommitSemantics(t *testing.T) {
	db := testDB(t)
	obj, _ := objstore.NewFS(t.TempDir())
	svc := &Service{DB: db, Obj: obj}
	p := testPrincipal(t, db)
	ctx := context.Background()
	run := "run-" + uuid.NewString()[:8]
	rec := run + "#0000"
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: rec, CaptureRunID: run, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: rec, CaptureRunID: run, SchemaVersion: 1}); err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	if err := svc.CreateRecording(ctx, p, CreateRecordingRequest{RecordingID: rec, CaptureRunID: run + "-other", SchemaVersion: 1}); err == nil {
		t.Fatal("expected recording identity conflict")
	} else if st, code := apiCode(err); st != 409 || code != "recording_conflict" {
		t.Fatalf("want recording_conflict got %v", err)
	}
	// unknown recording -> 404
	if _, err := svc.UploadBatch(ctx, p, "nope", body(t, events("nope", 1, 3))); err == nil {
		t.Fatal("expected error")
	} else if st, _ := apiCode(err); st != 404 {
		t.Fatalf("want 404 got %v", err)
	}
	// 1..10 durable=10
	res, err := svc.UploadBatch(ctx, p, rec, body(t, events(rec, 1, 10)))
	if err != nil || res.DurableSeq != 10 {
		t.Fatalf("first batch: %v %+v", err, res)
	}
	// out of order: 21..30 -> durable stays 10
	res, err = svc.UploadBatch(ctx, p, rec, body(t, events(rec, 21, 10)))
	if err != nil || res.DurableSeq != 10 {
		t.Fatalf("gap batch: %v %+v", err, res)
	}
	// duplicate identical -> idempotent
	res, err = svc.UploadBatch(ctx, p, rec, body(t, events(rec, 21, 10)))
	if err != nil || !res.Duplicate || res.DurableSeq != 10 {
		t.Fatalf("dup: %v %+v", err, res)
	}
	// same range different content -> 409 batch_conflict
	alt := events(rec, 21, 10)
	alt[0].Payload = json.RawMessage(`{"raw":"tampered"}`)
	_, err = svc.UploadBatch(ctx, p, rec, body(t, alt))
	if st, code := apiCode(err); st != 409 || code != "batch_conflict" {
		t.Fatalf("want batch_conflict got %v", err)
	}
	// overlapping different boundaries -> 409 batch_overlap
	_, err = svc.UploadBatch(ctx, p, rec, body(t, events(rec, 25, 10)))
	if st, code := apiCode(err); st != 409 || code != "batch_overlap" {
		t.Fatalf("want batch_overlap got %v", err)
	}
	// fill the hole 11..20 -> durable jumps to 30
	res, err = svc.UploadBatch(ctx, p, rec, body(t, events(rec, 11, 10)))
	if err != nil || res.DurableSeq != 30 {
		t.Fatalf("hole fill: %v %+v", err, res)
	}
	// corrupted hash -> 400 hash_mismatch
	hdr, comp, _ := protocol.EncodeBatch(events(rec, 31, 2), nil)
	hdr.SHA256 = "00" + hdr.SHA256[2:]
	var bad bytes.Buffer
	_ = protocol.WriteBatchBody(&bad, hdr, comp)
	_, err = svc.UploadBatch(ctx, p, rec, &bad)
	if st, code := apiCode(err); st != 400 || code != "hash_mismatch" {
		t.Fatalf("want hash_mismatch got %v", err)
	}
	// integrity alert recorded for the conflict
	var alerts json.RawMessage
	_ = db.Pool.QueryRow(ctx, `select integrity_alerts from recordings where id=$1`, rec).Scan(&alerts)
	if !bytes.Contains(alerts, []byte("batch_conflict")) {
		t.Fatalf("expected integrity alert, got %s", alerts)
	}
	// decode jobs enqueued: one per accepted batch (3)
	var n int
	_ = db.Pool.QueryRow(ctx, `select count(*) from processing_jobs where recording_id=$1 and type='decode'`, rec).Scan(&n)
	if n != 3 {
		t.Fatalf("want 3 decode jobs got %d", n)
	}
	// seal, then a further batch is still accepted (backfill window) but state stays sealed
	manifest := json.RawMessage(`{"claim":"best-effort"}`)
	if err := svc.Seal(ctx, p, rec, SealRequest{FinalSeq: 32, Manifest: manifest, ManifestSHA256: protocol.SHA256Hex(manifest)}); err != nil {
		t.Fatal(err)
	}
	res, err = svc.UploadBatch(ctx, p, rec, body(t, events(rec, 31, 2)))
	if err != nil || res.DurableSeq != 32 || res.State != "sealed" {
		t.Fatalf("backfill after seal: %v %+v", err, res)
	}
	var jobsBefore int
	_ = db.Pool.QueryRow(ctx, `select count(*) from processing_jobs where recording_id=$1`, rec).Scan(&jobsBefore)
	if err := svc.Seal(ctx, p, rec, SealRequest{FinalSeq: 32, Manifest: manifest, ManifestSHA256: protocol.SHA256Hex(manifest)}); err != nil {
		t.Fatalf("idempotent seal: %v", err)
	}
	var jobsAfter int
	_ = db.Pool.QueryRow(ctx, `select count(*) from processing_jobs where recording_id=$1`, rec).Scan(&jobsAfter)
	if jobsAfter != jobsBefore {
		t.Fatalf("idempotent seal enqueued work: before=%d after=%d", jobsBefore, jobsAfter)
	}
	otherManifest := json.RawMessage(`{"claim":"client-complete"}`)
	if err := svc.Seal(ctx, p, rec, SealRequest{FinalSeq: 32, Manifest: otherManifest, ManifestSHA256: protocol.SHA256Hex(otherManifest)}); err == nil {
		t.Fatal("expected manifest conflict")
	} else if st, code := apiCode(err); st != 409 || code != "manifest_conflict" {
		t.Fatalf("want manifest_conflict got %v", err)
	}
	if err := svc.Seal(ctx, p, rec, SealRequest{FinalSeq: 31}); err == nil {
		t.Fatal("expected final sequence conflict")
	} else if st, code := apiCode(err); st != 409 || code != "final_seq_conflict" {
		t.Fatalf("want final_seq_conflict got %v", err)
	}
	// other project cannot upload
	other := testPrincipal(t, db)
	_, err = svc.UploadBatch(ctx, other, rec, body(t, events(rec, 33, 1)))
	if st, _ := apiCode(err); st != 403 {
		t.Fatalf("want 403 got %v", err)
	}
}

func TestCaptureRunCollectorBindingAndMetadataValidation(t *testing.T) {
	db := testDB(t)
	obj, _ := objstore.NewFS(t.TempDir())
	svc := &Service{DB: db, Obj: obj}
	p := testPrincipal(t, db)
	p.CollectorID = uuid.New()
	run := "run-" + uuid.NewString()[:8]
	if err := svc.CreateRecording(context.Background(), p, CreateRecordingRequest{
		RecordingID: run + "#0000", CaptureRunID: run, SegmentNo: 0, SchemaVersion: 1,
		Run: &RunMetadata{Metadata: json.RawMessage(`{"source":"test"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	other := p
	other.CollectorID = uuid.New()
	if err := svc.CreateRecording(context.Background(), other, CreateRecordingRequest{
		RecordingID: run + "#0001", CaptureRunID: run, SegmentNo: 1, SchemaVersion: 1,
	}); err == nil {
		t.Fatal("different collector appended to an existing capture run")
	} else if st, code := apiCode(err); st != 409 || code != "capture_run_conflict" {
		t.Fatalf("unexpected collector binding error: %v", err)
	}
	if err := svc.CreateRecording(context.Background(), p, CreateRecordingRequest{
		RecordingID: "bad-meta", CaptureRunID: "bad-meta", SchemaVersion: 1,
		Run: &RunMetadata{Metadata: json.RawMessage(`[]`)},
	}); err == nil {
		t.Fatal("array run metadata was accepted")
	}

	unbound := testPrincipal(t, db)
	legacyRun := "run-legacy-" + uuid.NewString()[:8]
	if err := svc.CreateRecording(context.Background(), unbound, CreateRecordingRequest{RecordingID: legacyRun + "#0000", CaptureRunID: legacyRun, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	unbound.CollectorID = uuid.New()
	if err := svc.CreateRecording(context.Background(), unbound, CreateRecordingRequest{RecordingID: legacyRun + "#0000", CaptureRunID: legacyRun, SchemaVersion: 1}); err != nil {
		t.Fatalf("claim legacy upload run: %v", err)
	}
	var claimed uuid.UUID
	if err := db.Pool.QueryRow(context.Background(), `select collector_id from capture_runs where id=$1`, legacyRun).Scan(&claimed); err != nil || claimed != unbound.CollectorID {
		t.Fatalf("legacy run owner=%s err=%v", claimed, err)
	}
	imported := testPrincipal(t, db)
	importedRun := "run-import-" + uuid.NewString()[:8]
	if err := svc.CreateRecording(context.Background(), imported, CreateRecordingRequest{RecordingID: importedRun + "#0000", CaptureRunID: importedRun, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `update recordings set origin='import' where id=$1`, importedRun+"#0000"); err != nil {
		t.Fatal(err)
	}
	imported.CollectorID = uuid.New()
	if err := svc.CreateRecording(context.Background(), imported, CreateRecordingRequest{RecordingID: importedRun + "#0000", CaptureRunID: importedRun, SchemaVersion: 1}); err == nil {
		t.Fatal("collector claimed an imported capture run")
	} else if st, code := apiCode(err); st != 409 || code != "capture_run_conflict" {
		t.Fatalf("unexpected imported claim error: %v", err)
	}
}

func TestBlobUpload(t *testing.T) {
	db := testDB(t)
	obj, _ := objstore.NewFS(t.TempDir())
	svc := &Service{DB: db, Obj: obj}
	p := testPrincipal(t, db)
	ctx := context.Background()
	content := []byte(`{"big":"payload"}`)
	sha := protocol.SHA256Hex(content)
	// wrong digest
	_, err := svc.PutBlob(ctx, p, sha, "application/json", bytes.NewReader([]byte("other")))
	if st, code := apiCode(err); st != 422 || code != "hash_mismatch" {
		t.Fatalf("want 422 hash_mismatch got %v", err)
	}
	created, err := svc.PutBlob(ctx, p, sha, "application/json", bytes.NewReader(content))
	if err != nil || !created {
		t.Fatalf("put: %v %v", created, err)
	}
	created, err = svc.PutBlob(ctx, p, sha, "application/json", bytes.NewReader(content))
	if err != nil || created {
		t.Fatalf("second put should be no-op: %v %v", created, err)
	}
	ok, size, err := svc.BlobExists(ctx, p, sha)
	if err != nil || !ok || size != int64(len(content)) {
		t.Fatalf("exists: %v %v %d", ok, err, size)
	}
	// other project does not see it (per-project dedupe)
	other := testPrincipal(t, db)
	ok, _, _ = svc.BlobExists(ctx, other, sha)
	if ok {
		t.Fatal("blob leaked across projects")
	}

	limitedProject := testPrincipal(t, db)
	limited := &Service{DB: db, Obj: obj, MaxProjectStorageBytes: 4}
	tooLarge := []byte("12345")
	_, err = limited.PutBlob(ctx, limitedProject, protocol.SHA256Hex(tooLarge), "text/plain", bytes.NewReader(tooLarge))
	if st, code := apiCode(err); st != 429 || code != "storage_quota_exceeded" {
		t.Fatalf("want storage quota error got %v", err)
	}
	ok, _, err = limited.BlobExists(ctx, limitedProject, protocol.SHA256Hex(tooLarge))
	if err != nil || ok {
		t.Fatalf("quota-rejected blob entered catalog: exists=%v err=%v", ok, err)
	}
}

type failOncePutStore struct {
	objstore.Store
	failed bool
}

func (s *failOncePutStore) Put(ctx context.Context, key string, body io.Reader, size int64, mediaType string) error {
	if !s.failed {
		s.failed = true
		return errors.New("injected object publication failure")
	}
	return s.Store.Put(ctx, key, body, size, mediaType)
}

func TestBlobUploadRecoversDurablePublicationIntent(t *testing.T) {
	db := testDB(t)
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := testPrincipal(t, db)
	content := []byte("crash-safe-blob")
	digestBytes := sha256.Sum256(content)
	digest := protocol.SHA256Hex(content)
	failing := &failOncePutStore{Store: objects}
	service := &Service{DB: db, Obj: failing}

	if _, err := service.PutBlob(context.Background(), p, digest, "text/plain", bytes.NewReader(content)); err == nil {
		t.Fatal("injected publication failure was ignored")
	}
	var state string
	if err := db.Pool.QueryRow(context.Background(), `select state from blobs where project_id=$1 and sha256=$2`, p.ProjectID, digestBytes[:]).Scan(&state); err != nil || state != "uploading" {
		t.Fatalf("blob publication intent was not durable: state=%s err=%v", state, err)
	}
	if exists, _, err := service.BlobExists(context.Background(), p, digest); err != nil || exists {
		t.Fatalf("unfinished blob became readable: exists=%v err=%v", exists, err)
	}

	created, err := service.PutBlob(context.Background(), p, digest, "text/plain", bytes.NewReader(content))
	if err != nil || !created {
		t.Fatalf("retry did not activate durable intent: created=%v err=%v", created, err)
	}
	if err := db.Pool.QueryRow(context.Background(), `select state from blobs where project_id=$1 and sha256=$2`, p.ProjectID, digestBytes[:]).Scan(&state); err != nil || state != "active" {
		t.Fatalf("retried blob was not activated: state=%s err=%v", state, err)
	}
}

func TestBatchStorageQuotaPrecedesObjectCommit(t *testing.T) {
	db := testDB(t)
	obj, _ := objstore.NewFS(t.TempDir())
	svc := &Service{DB: db, Obj: obj, MaxProjectStorageBytes: 1}
	p := testPrincipal(t, db)
	run := "run-" + uuid.NewString()[:8]
	rec := run + "#0000"
	if err := svc.CreateRecording(context.Background(), p, CreateRecordingRequest{RecordingID: rec, CaptureRunID: run, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.UploadBatch(context.Background(), p, rec, body(t, events(rec, 1, 1)))
	if st, code := apiCode(err); st != 429 || code != "storage_quota_exceeded" {
		t.Fatalf("want storage quota error got %v", err)
	}
	var batches int
	if err := db.Pool.QueryRow(context.Background(), `select count(*) from batches where recording_id=$1`, rec).Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if batches != 0 {
		t.Fatalf("quota-rejected batch entered catalog: %d", batches)
	}
}

func TestOrphanedObjectCannotPoisonCatalog(t *testing.T) {
	db := testDB(t)
	obj, _ := objstore.NewFS(t.TempDir())
	svc := &Service{DB: db, Obj: obj}
	p := testPrincipal(t, db)
	run := "run-" + uuid.NewString()[:8]
	rec := run + "#0000"
	if err := svc.CreateRecording(context.Background(), p, CreateRecordingRequest{RecordingID: rec, CaptureRunID: run, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	poisonEvents := events(rec, 1, 1)
	poisonEvents[0].Payload = json.RawMessage(`{"raw":"poison"}`)
	poison := body(t, poisonEvents).Bytes()
	key := objstore.RecordingPrefix(p.TenantID.String(), p.ProjectID.String(), rec) + protocol.BatchObjectKey(1, 1)
	if err := obj.Put(context.Background(), key, bytes.NewReader(poison), int64(len(poison)), protocol.ContentTypeBatch); err != nil {
		t.Fatal(err)
	}
	_, err := svc.UploadBatch(context.Background(), p, rec, body(t, events(rec, 1, 1)))
	if st, code := apiCode(err); st != 409 || code != "object_conflict" {
		t.Fatalf("poisoned batch object was accepted: %v", err)
	}
	var batches int
	if err := db.Pool.QueryRow(context.Background(), `select count(*) from batches where recording_id=$1`, rec).Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if batches != 0 {
		t.Fatal("poisoned batch entered catalog")
	}

	expected := []byte("expected")
	sha := protocol.SHA256Hex(expected)
	blobKey := objstore.BlobKey(p.TenantID.String(), p.ProjectID.String(), sha)
	if err := obj.Put(context.Background(), blobKey, strings.NewReader("poisoned"), 8, "text/plain"); err != nil {
		t.Fatal(err)
	}
	_, err = svc.PutBlob(context.Background(), p, sha, "text/plain", bytes.NewReader(expected))
	if st, code := apiCode(err); st != 409 || code != "object_conflict" {
		t.Fatalf("poisoned blob object was accepted: %v", err)
	}
	if ok, _, err := svc.BlobExists(context.Background(), p, sha); err != nil || ok {
		t.Fatalf("poisoned blob entered catalog: exists=%v err=%v", ok, err)
	}
}
