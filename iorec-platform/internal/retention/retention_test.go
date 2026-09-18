package retention

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func retentionTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

type retentionFixture struct {
	tenant, project, collector uuid.UUID
	principal                  auth.Principal
}

func newRetentionFixture(t *testing.T, db *store.DB) retentionFixture {
	t.Helper()
	fixture := retentionFixture{tenant: uuid.New(), project: uuid.New(), collector: uuid.New()}
	fixture.principal = auth.Principal{Kind: auth.KindUser, TenantID: fixture.tenant, ProjectID: fixture.project, Subject: "admin@test", Role: auth.RoleAdmin}
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, fixture.tenant, "retention-"+fixture.tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,$3)`, fixture.project, fixture.tenant, "retention-"+fixture.project.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into collectors(id,project_id,name,version,hostname,os) values($1,$2,'collector','test','host','linux')`, fixture.collector, fixture.project); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func putObject(t *testing.T, objectStore objstore.Store, key string, value []byte) {
	t.Helper()
	if err := objectStore.Put(context.Background(), key, bytes.NewReader(value), int64(len(value)), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
}

type failOnceDeleteStore struct {
	*objstore.FS
	failed bool
}

func (s *failOnceDeleteStore) Delete(ctx context.Context, key string) error {
	if !s.failed {
		s.failed = true
		return errors.New("injected object deletion failure")
	}
	return s.FS.Delete(ctx, key)
}

func TestFullDeletionIsDurableScopedAndPropagated(t *testing.T) {
	db := retentionTestDB(t)
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: objects}
	fixture := newRetentionFixture(t, db)
	ctx := context.Background()
	run := "delete-run-" + uuid.NewString()
	recording := run + "#0000"
	otherRun := "keep-run-" + uuid.NewString()
	otherRecording := otherRun + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,collector_id,ended_at) values($1,$3,$4,now()),($2,$3,null,now())`, run, otherRun, fixture.project, fixture.collector); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set benchmark_result='{"result":{"task":"private-task"}}' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,final_seq,durable_seq,parsed_seq) values($1,$3,$4,'sealed',1,1,1),($2,$3,$5,'sealed',1,1,1)`, recording, otherRecording, fixture.project, run, otherRun); err != nil {
		t.Fatal(err)
	}
	uniqueValue, sharedValue := []byte("unique-sensitive-body"), []byte("shared-body")
	uniqueSHA, sharedSHA := sha256.Sum256(uniqueValue), sha256.Sum256(sharedValue)
	uniqueKey := objstore.BlobKey(fixture.tenant.String(), fixture.project.String(), fmtDigest(uniqueSHA))
	sharedKey := objstore.BlobKey(fixture.tenant.String(), fixture.project.String(), fmtDigest(sharedSHA))
	eventID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	event := protocol.Event{
		SchemaVersion: 1,
		EventID:       eventID.String(),
		Seq:           1,
		RunID:         run,
		RecordingID:   recording,
		Source:        protocol.SourceProxy,
		Event:         protocol.EvResponseBody,
		MonotonicNS:   1,
		WallTime:      time.Now().UTC(),
		PayloadRef:    &protocol.PayloadRef{SHA256: "sha256:" + fmtDigest(uniqueSHA), Size: int64(len(uniqueValue)), MediaType: "application/octet-stream"},
		Redaction:     &protocol.Redaction{Policy: "test"},
	}
	header, compressed, err := protocol.EncodeBatch([]protocol.Event{event}, []protocol.BlobRef{
		{SHA256: fmtDigest(uniqueSHA), Size: int64(len(uniqueValue))},
		{SHA256: fmtDigest(sharedSHA), Size: int64(len(sharedValue))},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := protocol.WriteBatchBody(&wire, header, compressed); err != nil {
		t.Fatal(err)
	}
	batchKey := objstore.RecordingPrefix(fixture.tenant.String(), fixture.project.String(), recording) + protocol.BatchObjectKey(1, 1)
	putObject(t, objects, batchKey, wire.Bytes())
	batchDigest, err := hex.DecodeString(header.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into batches(recording_id,batch_id,first_seq,last_seq,event_count,byte_length,sha256,object_key) values($1,$2,1,1,1,$3,$4,$5)`, recording, header.BatchID, header.ByteLength, batchDigest, batchKey); err != nil {
		t.Fatal(err)
	}
	putObject(t, objects, uniqueKey, uniqueValue)
	putObject(t, objects, sharedKey, sharedValue)
	if _, err := db.Pool.Exec(ctx, `insert into blobs(project_id,sha256,size,object_key,ref_count) values($1,$2,$3,$4,1),($1,$5,$6,$7,2)`, fixture.project, uniqueSHA[:], len(uniqueValue), uniqueKey, sharedSHA[:], len(sharedValue), sharedKey); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_blob_refs(recording_id,project_id,sha256) values($1,$3,$4),($1,$3,$5),($2,$3,$5)`, recording, otherRecording, fixture.project, uniqueSHA[:], sharedSHA[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,payload_sha256,batch_id) values($1,1,1,now(),'proxy','response_body',$2,'batch')`, recording, uniqueSHA[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,request_body_ref,processor_version) values($1,'native',$2,$3,$4,'proxy',$5,'test')`, run+"~attempt", recording, fixture.project, run, uniqueSHA[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into sessions(id,project_id,capture_run_id,kind,turns,inference_count,relation_revision) values($1,$2,$3,'native','[]',0,1)`, run+"~session", fixture.project, run); err != nil {
		t.Fatal(err)
	}
	staleControl := uuid.New()
	if _, err := db.Pool.Exec(ctx, `insert into collector_requests(id,collector_id,project_id,type,payload,status,created_by) values($1,$2,$3,'backfill',jsonb_build_object('recording_id',$4::text),'acked','operator@test')`, staleControl, fixture.collector, fixture.project, recording); err != nil {
		t.Fatal(err)
	}

	status, err := service.RequestDelete(ctx, fixture.principal, "recording", recording, DeleteRequest{Confirmation: recording, Reason: "test erasure"})
	if err != nil {
		t.Fatal(err)
	}
	if status.CaptureRunID != run || status.State != "pending" || status.CollectorRequestID == nil {
		t.Fatalf("unexpected deletion status: %+v", status)
	}
	var staleState string
	if err := db.Pool.QueryRow(ctx, `select status from collector_requests where id=$1`, staleControl).Scan(&staleState); err != nil || staleState != "expired" {
		t.Fatalf("recoverable control work survived deletion fence: state=%s err=%v", staleState, err)
	}
	var expires *time.Time
	if err := db.Pool.QueryRow(ctx, `select expires_at from collector_requests where id=$1`, *status.CollectorRequestID).Scan(&expires); err != nil || expires != nil {
		t.Fatalf("propagated request must survive offline collectors: expires=%v err=%v", expires, err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var runState, recState, deletionState string
	if err := db.Pool.QueryRow(ctx, `select c.state,r.state,d.state from capture_runs c join recordings r on r.capture_run_id=c.id join deletion_requests d on d.capture_run_id=c.id and d.mode='full' where c.id=$1`, run).Scan(&runState, &recState, &deletionState); err != nil {
		t.Fatal(err)
	}
	if runState != "deleted" || recState != "deleted" || deletionState != "local_pending" {
		t.Fatalf("remote deletion did not converge: run=%s recording=%s request=%s", runState, recState, deletionState)
	}
	var benchmarkScrubbed bool
	if err := db.Pool.QueryRow(ctx, `select benchmark_result is null from capture_runs where id=$1`, run).Scan(&benchmarkScrubbed); err != nil || !benchmarkScrubbed {
		t.Fatalf("benchmark annotation not scrubbed: %v", err)
	}
	for table, query := range map[string]string{
		"batches":          `select count(*) from batches where recording_id=$1`,
		"recording_events": `select count(*) from recording_events where recording_id=$1`,
		"model_attempts":   `select count(*) from model_attempts where capture_run_id=$1`,
		"sessions":         `select count(*) from sessions where capture_run_id=$1`,
	} {
		var count int
		id := run
		if table == "batches" || table == "recording_events" {
			id = recording
		}
		if err := db.Pool.QueryRow(ctx, query, id).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s retained deleted facts: count=%d err=%v", table, count, err)
		}
	}
	if _, err := objects.Stat(ctx, batchKey); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("batch object retained: %v", err)
	}
	if _, err := objects.Stat(ctx, uniqueKey); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("unique blob retained: %v", err)
	}
	if size, err := objects.Stat(ctx, sharedKey); err != nil || size != int64(len(sharedValue)) {
		t.Fatalf("shared blob was erased: size=%d err=%v", size, err)
	}
	var sharedRefs, sharedRefCount int
	if err := db.Pool.QueryRow(ctx, `select count(*) from recording_blob_refs where project_id=$1 and sha256=$2`, fixture.project, sharedSHA[:]).Scan(&sharedRefs); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select ref_count from blobs where project_id=$1 and sha256=$2`, fixture.project, sharedSHA[:]).Scan(&sharedRefCount); err != nil || sharedRefs != 1 || sharedRefCount != 1 {
		t.Fatalf("shared refcount wrong: refs=%d count=%d err=%v", sharedRefs, sharedRefCount, err)
	}
	if _, err := db.Pool.Exec(ctx, `update collector_requests set status='done',finished_at=now() where id=$1`, *status.CollectorRequestID); err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select state from deletion_requests where id=$1`, status.ID).Scan(&deletionState); err != nil || deletionState != "done" {
		t.Fatalf("local propagation did not complete: state=%s err=%v", deletionState, err)
	}
	repeated, err := service.RequestDelete(ctx, fixture.principal, "recording", recording, DeleteRequest{Confirmation: recording})
	if err != nil || repeated.ID != status.ID {
		t.Fatalf("idempotent delete changed identity: repeated=%+v err=%v", repeated, err)
	}
}

func TestRawEvidenceTTLExpiresBodiesButKeepsMetadata(t *testing.T) {
	db := retentionTestDB(t)
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: objects}
	fixture := newRetentionFixture(t, db)
	ctx := context.Background()
	run := "ttl-run-" + uuid.NewString()
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,ended_at,retention_until) values($1,$2,now(),now()+interval '1 day')`, run, fixture.project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,final_seq,durable_seq,parsed_seq,retention_until) values($1,$2,$3,'sealed',1,1,1,now()-interval '1 second')`, recording, fixture.project, run); err != nil {
		t.Fatal(err)
	}
	value := []byte("ttl-sensitive-body")
	digest := sha256.Sum256(value)
	key := objstore.BlobKey(fixture.tenant.String(), fixture.project.String(), fmtDigest(digest))
	putObject(t, objects, key, value)
	if _, err := db.Pool.Exec(ctx, `insert into blobs(project_id,sha256,size,object_key,ref_count) values($1,$2,$3,$4,1)`, fixture.project, digest[:], len(value), key); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_blob_refs(recording_id,project_id,sha256) values($1,$2,$3)`, recording, fixture.project, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,request_headers,request_body,request_body_ref,response_text,normalized,processor_version) values($1,'native',$2,$3,$4,'proxy','{}','{"secret":true}',$5,'PHI','{"response":"PHI"}','test')`, run+"~attempt", recording, fixture.project, run, digest[:]); err != nil {
		t.Fatal(err)
	}
	leasedJob := uuid.New()
	if _, err := db.Pool.Exec(ctx, `insert into processing_jobs(id,project_id,type,capture_run_id,processor_version,dedupe_key,status,lease_owner,lease_until) values($1,$2,'resolve',$3,'test',$4,'leased','worker',now()+interval '1 minute')`, leasedJob, fixture.project, run, "ttl-leased-"+leasedJob.String()); err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var waitingState, waitingDeletion string
	if err := db.Pool.QueryRow(ctx, `select r.state,d.state from recordings r join deletion_requests d on d.recording_id=r.id and d.mode='evidence' where r.id=$1`, recording).Scan(&waitingState, &waitingDeletion); err != nil {
		t.Fatal(err)
	}
	if waitingState != "expiring" || waitingDeletion != "waiting_workers" {
		t.Fatalf("run-level worker was not fenced: recording=%s deletion=%s", waitingState, waitingDeletion)
	}
	if _, err := objects.Stat(ctx, key); err != nil {
		t.Fatalf("evidence was erased while a run-level worker was leased: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `update processing_jobs set status='done',lease_owner=null,lease_until=null,finished_at=now() where id=$1`, leasedJob); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `update deletion_requests set next_attempt_at=now() where recording_id=$1 and mode='evidence'`, recording); err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var body, response, normalized any
	if err := db.Pool.QueryRow(ctx, `select r.state,a.request_body,a.response_text,a.normalized from recordings r join model_attempts a on a.recording_id=r.id where r.id=$1`, recording).Scan(&state, &body, &response, &normalized); err != nil {
		t.Fatal(err)
	}
	if state != "expired" || body != nil || response != nil || normalized != nil {
		t.Fatalf("TTL did not scrub body fields: state=%s body=%v response=%v normalized=%v", state, body, response, normalized)
	}
	if _, err := objects.Stat(ctx, key); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("TTL blob retained: %v", err)
	}
	var runState string
	if err := db.Pool.QueryRow(ctx, `select state from capture_runs where id=$1`, run).Scan(&runState); err != nil || runState != "active" {
		t.Fatalf("raw TTL erased metadata run: state=%s err=%v", runState, err)
	}
}

func TestObjectDeletionFailureIsDurableAndRetryable(t *testing.T) {
	db := retentionTestDB(t)
	filesystem, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &failOnceDeleteStore{FS: filesystem}
	service := &Service{DB: db, Obj: objects}
	fixture := newRetentionFixture(t, db)
	ctx := context.Background()
	run := "retry-delete-run-" + uuid.NewString()
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,ended_at) values($1,$2,now())`, run, fixture.project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,final_seq,durable_seq,parsed_seq) values($1,$2,$3,'sealed',1,1,1)`, recording, fixture.project, run); err != nil {
		t.Fatal(err)
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	header, compressed, err := protocol.EncodeBatch([]protocol.Event{{
		SchemaVersion: 1,
		EventID:       eventID.String(),
		Seq:           1,
		RunID:         run,
		RecordingID:   recording,
		Source:        protocol.SourceProxy,
		Event:         protocol.EvAttemptEnd,
		MonotonicNS:   1,
		WallTime:      time.Now().UTC(),
		Redaction:     &protocol.Redaction{Policy: "test"},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := protocol.WriteBatchBody(&wire, header, compressed); err != nil {
		t.Fatal(err)
	}
	batchKey := objstore.RecordingPrefix(fixture.tenant.String(), fixture.project.String(), recording) + protocol.BatchObjectKey(1, 1)
	putObject(t, objects, batchKey, wire.Bytes())
	status, err := service.RequestDelete(ctx, fixture.principal, "capture_run", run, DeleteRequest{Confirmation: run})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var requestState, objectState string
	var attempts int
	var lastError *string
	if err := db.Pool.QueryRow(ctx, `select d.state,o.state,o.attempts,o.last_error from deletion_requests d join deletion_objects o on o.deletion_request_id=d.id where d.id=$1 and o.object_key=$2`, status.ID, batchKey).Scan(&requestState, &objectState, &attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if requestState != "deleting_objects" || objectState != "pending" || attempts != 1 || lastError == nil {
		t.Fatalf("object failure was not persisted for retry: request=%s object=%s attempts=%d error=%v", requestState, objectState, attempts, lastError)
	}
	if _, err := objects.Stat(ctx, batchKey); err != nil {
		t.Fatalf("failed delete unexpectedly removed the object: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `update deletion_objects set next_attempt_at=now() where deletion_request_id=$1`, status.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var runState, recordingState string
	if err := db.Pool.QueryRow(ctx, `select d.state,c.state,r.state from deletion_requests d join capture_runs c on c.id=d.capture_run_id join recordings r on r.capture_run_id=c.id where d.id=$1`, status.ID).Scan(&requestState, &runState, &recordingState); err != nil {
		t.Fatal(err)
	}
	if requestState != "done" || runState != "deleted" || recordingState != "deleted" {
		t.Fatalf("retry did not converge: request=%s run=%s recording=%s", requestState, runState, recordingState)
	}
	if _, err := objects.Stat(ctx, batchKey); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("retried object deletion did not remove object: %v", err)
	}
}

func TestFullDeletionDominatesOverlappingEvidenceTTL(t *testing.T) {
	db := retentionTestDB(t)
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: objects}
	fixture := newRetentionFixture(t, db)
	ctx := context.Background()
	run := "overlap-run-" + uuid.NewString()
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,ended_at,retention_until) values($1,$2,now(),now()+interval '1 day')`, run, fixture.project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,final_seq,durable_seq,parsed_seq,retention_until) values($1,$2,$3,'sealed',1,1,1,now()-interval '1 second')`, recording, fixture.project, run); err != nil {
		t.Fatal(err)
	}

	// Enqueue evidence expiry, but do not advance it yet. A user-requested full
	// deletion arriving in this window must win even if the older evidence work
	// is finalized after the full deletion.
	if err := service.enqueueDueEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	var evidenceID uuid.UUID
	if err := db.Pool.QueryRow(ctx, `select id from deletion_requests where project_id=$1 and recording_id=$2 and mode='evidence'`, fixture.project, recording).Scan(&evidenceID); err != nil {
		t.Fatal(err)
	}
	full, err := service.RequestDelete(ctx, fixture.principal, "capture_run", run, DeleteRequest{Confirmation: run, Reason: "overlap test"})
	if err != nil {
		t.Fatal(err)
	}
	// Force the full request to be prepared and finalized first. This exercises
	// the lifecycle guard in evidence finalization rather than relying on normal
	// request-time ordering.
	if _, err := db.Pool.Exec(ctx, `update deletion_requests set requested_at=case when id=$1 then now()-interval '1 hour' else now() end,next_attempt_at=now() where id in ($1,$2)`, full.ID, evidenceID); err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}

	var runState, recordingState, deletedBy, fullState, evidenceState string
	if err := db.Pool.QueryRow(ctx, `select c.state,r.state,r.deleted_by,fd.state,ed.state from capture_runs c join recordings r on r.capture_run_id=c.id join deletion_requests fd on fd.id=$2 join deletion_requests ed on ed.id=$3 where c.id=$1`, run, full.ID, evidenceID).Scan(&runState, &recordingState, &deletedBy, &fullState, &evidenceState); err != nil {
		t.Fatal(err)
	}
	if runState != "deleted" || recordingState != "deleted" || deletedBy != fixture.principal.Subject || fullState != "done" || evidenceState != "done" {
		t.Fatalf("overlapping evidence work regressed full deletion: run=%s recording=%s deleted_by=%s full=%s evidence=%s", runState, recordingState, deletedBy, fullState, evidenceState)
	}
}

func TestStaleBlobUploadIntentGCRequiresNoReferences(t *testing.T) {
	db := retentionTestDB(t)
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: objects}
	fixture := newRetentionFixture(t, db)
	ctx := context.Background()
	run := "blob-gc-run-" + uuid.NewString()
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,ended_at) values($1,$2,now())`, run, fixture.project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,final_seq,durable_seq,parsed_seq) values($1,$2,$3,'sealed',1,1,1)`, recording, fixture.project, run); err != nil {
		t.Fatal(err)
	}
	unreferencedValue := []byte("stale-unreferenced-upload")
	referencedValue := []byte("stale-referenced-upload")
	unreferencedDigest := sha256.Sum256(unreferencedValue)
	referencedDigest := sha256.Sum256(referencedValue)
	unreferencedKey := objstore.BlobKey(fixture.tenant.String(), fixture.project.String(), fmtDigest(unreferencedDigest))
	referencedKey := objstore.BlobKey(fixture.tenant.String(), fixture.project.String(), fmtDigest(referencedDigest))
	putObject(t, objects, unreferencedKey, unreferencedValue)
	putObject(t, objects, referencedKey, referencedValue)
	if _, err := db.Pool.Exec(ctx, `insert into blobs(project_id,sha256,size,object_key,ref_count,state,first_seen_at) values($1,$2,$3,$4,0,'uploading',now()-interval '25 hours'),($1,$5,$6,$7,1,'uploading',now()-interval '25 hours')`, fixture.project, unreferencedDigest[:], len(unreferencedValue), unreferencedKey, referencedDigest[:], len(referencedValue), referencedKey); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_blob_refs(recording_id,project_id,sha256) values($1,$2,$3)`, recording, fixture.project, referencedDigest[:]); err != nil {
		t.Fatal(err)
	}

	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Stat(ctx, unreferencedKey); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("stale unreferenced upload object retained: %v", err)
	}
	if size, err := objects.Stat(ctx, referencedKey); err != nil || size != int64(len(referencedValue)) {
		t.Fatalf("referenced upload intent was erased: size=%d err=%v", size, err)
	}
	var unreferencedRows int
	if err := db.Pool.QueryRow(ctx, `select count(*) from blobs where project_id=$1 and sha256=$2`, fixture.project, unreferencedDigest[:]).Scan(&unreferencedRows); err != nil || unreferencedRows != 0 {
		t.Fatalf("stale upload catalog row retained: count=%d err=%v", unreferencedRows, err)
	}
	var referencedState string
	if err := db.Pool.QueryRow(ctx, `select state from blobs where project_id=$1 and sha256=$2`, fixture.project, referencedDigest[:]).Scan(&referencedState); err != nil || referencedState != "uploading" {
		t.Fatalf("referenced upload intent changed: state=%s err=%v", referencedState, err)
	}
	var auditRows int
	if err := db.Pool.QueryRow(ctx, `select count(*) from audit_log where project_id=$1 and action='retention.orphan_blob_delete' and entity_id=$2`, fixture.project, fmtDigest(unreferencedDigest)).Scan(&auditRows); err != nil || auditRows != 1 {
		t.Fatalf("stale upload deletion was not audited: count=%d err=%v", auditRows, err)
	}
}

func TestDeleteAuthorizationConfirmationAndScopeEscalation(t *testing.T) {
	db := retentionTestDB(t)
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: objects}
	fixture := newRetentionFixture(t, db)
	ctx := context.Background()
	viewer := fixture.principal
	viewer.Role = auth.RoleViewer
	if _, err := service.RequestDelete(ctx, viewer, "capture_run", "missing", DeleteRequest{Confirmation: "missing"}); err == nil {
		t.Fatal("viewer initiated irreversible deletion")
	}
	run := "session-delete-run-" + uuid.NewString()
	recording := run + "#0000"
	laterRecording := run + "#0001"
	session := run + "~session"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,collector_id,ended_at) values($1,$2,$3,now())`, run, fixture.project, fixture.collector); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,final_seq,durable_seq,parsed_seq) values($1,$2,$3,'sealed',1,1,1)`, recording, fixture.project, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,segment_no,sequence_base,state,final_seq,durable_seq,parsed_seq) values($1,$2,$3,1,1,'sealed',2,2,2)`, laterRecording, fixture.project, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into sessions(id,project_id,capture_run_id,kind,turns,inference_count,relation_revision) values($1,$2,$3,'native','[]',0,1)`, session, fixture.project, run); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RequestDelete(ctx, fixture.principal, "session", session, DeleteRequest{Confirmation: "wrong"}); err == nil {
		t.Fatal("mismatched confirmation initiated deletion")
	}
	status, err := service.RequestDelete(ctx, fixture.principal, "session", session, DeleteRequest{Confirmation: session})
	if err != nil {
		t.Fatal(err)
	}
	if status.CaptureRunID != run || status.RequestedEntityType != "session" || status.RequestedEntityID != session {
		t.Fatalf("session deletion was not explicitly escalated: %+v", status)
	}
	var payload []byte
	if err := db.Pool.QueryRow(ctx, `select payload from collector_requests where id=$1`, *status.CollectorRequestID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var payloadObject map[string]any
	if err := json.Unmarshal(payload, &payloadObject); err != nil || payloadObject["recording_id"] != recording {
		t.Fatalf("whole-run deletion was not addressed through segment zero: %s", payload)
	}
	repeated, err := service.RequestDelete(ctx, fixture.principal, "session", session, DeleteRequest{Confirmation: session})
	if err != nil || repeated.ID != status.ID {
		t.Fatalf("session deletion was not idempotent: repeated=%+v err=%v", repeated, err)
	}
}

func TestPolicyParsingFailsClosed(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"retention":{"raw_evidence_days":0,"metadata_days":9999}}`), []byte(`not-json`)} {
		if got := PolicyFromSettings(raw); got != DefaultPolicy() {
			t.Fatalf("malformed settings did not use defaults: raw=%q got=%+v", raw, got)
		}
	}
	custom := PolicyFromSettings([]byte(`{"retention":{"raw_evidence_days":30,"metadata_days":180}}`))
	if custom.RawEvidenceDays != 30 || custom.MetadataDays != 180 {
		t.Fatalf("valid settings ignored: %+v", custom)
	}
}

func fmtDigest(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, sha256.Size*2)
	for index, b := range value {
		out[index*2] = digits[b>>4]
		out[index*2+1] = digits[b&0x0f]
	}
	return string(out)
}
