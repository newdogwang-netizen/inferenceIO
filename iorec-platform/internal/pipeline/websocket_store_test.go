package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
)

func TestWebSocketCallProjectionDatabaseReplay(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-ws-calls-" + uuid.NewString()
	rec, rec2 := run+"#0000", run+"#0001"
	for _, step := range []struct {
		q    string
		args []any
	}{
		{`insert into tenants(id,name) values($1,'ws-test')`, []any{tenant}},
		{`insert into projects(id,tenant_id,name) values($1,$2,'ws-test')`, []any{project, tenant}},
		{`insert into capture_runs(id,project_id) values($1,$2)`, []any{run, project}},
		{`insert into recordings(id,project_id,capture_run_id,segment_no,state) values($1,$2,$3,0,'sealed'),($4,$2,$3,1,'sealed')`, []any{rec, project, run, rec2}},
	} {
		if _, err := db.Pool.Exec(ctx, step.q, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	objects, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &Deps{DB: db, Obj: objects}
	job := &jobs.Job{ProjectID: project, CaptureRunID: &run, RecordingID: &rec}
	frames := wsFixture(
		`>{"type":"response.create","model":"ws\u0000test","input":"one"}`,
		`{"type":"response.created","response":{"id":"r1\u0000"}}`,
		`{"type":"response.completed","response":{"id":"r1\u0000","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"first\u0000answer"}]}],"usage":{"input_tokens":10,"output_tokens":5}}}`,
		`>{"type":"response.create","model":"ws-test","previous_response_id":"r1\u0000","input":"two"}`,
		`{"type":"response.created","response":{"id":"r2"}}`,
		`{"type":"response.completed","response":{"id":"r2","status":"completed","output":[],"usage":{"input_tokens":20,"output_tokens":2}}}`,
	)
	now := time.Now().UTC()
	for conn := 0; conn < 2; conn++ {
		native := fmt.Sprintf("conn-%d", conn)
		parent := AttemptKey(run, native)
		if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,protocol,api_mode,terminal_state,error_class,normalized,usage,processor_version) values($1,$2,$3,$4,$5,'proxy','websocket','responses','error','client_read','{"response_text":"legacy aggregate"}','{"output_tokens":999}','old')`, parent, native, rec, project, run); err != nil {
			t.Fatal(err)
		}
		counts := map[string]int64{}
		for i, f := range frames {
			seq := int64(conn*100 + i + 1)
			recording := rec
			if i >= 4 {
				recording = rec2
			}
			counts[f.Meta.Direction]++
			digest := sha256.Sum256(f.Body)
			key := "ws/" + hex.EncodeToString(digest[:])
			if err := objects.Put(ctx, key, bytes.NewReader(f.Body), int64(len(f.Body)), "application/json"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Pool.Exec(ctx, `insert into blobs(project_id,sha256,size,object_key) values($1,$2,$3,$4) on conflict do nothing`, project, digest[:], len(f.Body), key); err != nil {
				t.Fatal(err)
			}
			meta, _ := json.Marshal(websocketFrameMetadata{Direction: f.Meta.Direction, MessageSequence: counts[f.Meta.Direction], Opcode: "text", ObservedSize: int64(len(f.Body)), CapturedSize: int64(len(f.Body)), SHA256: hex.EncodeToString(digest[:])})
			if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,payload_sha256,payload_size,batch_id) values($1,$2,$2,$3,'proxy','websocket_frame',$4,$5,$6,$7,'fixture')`, recording, seq, now.Add(time.Duration(seq)*time.Millisecond), native, meta, digest[:], len(f.Body)); err != nil {
				t.Fatal(err)
			}
		}
		meta, _ := json.Marshal(websocketFinishMetadata{ClientMessages: 2, UpstreamMessages: 4})
		if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,terminal_state,batch_id) values($1,$2,$2,$3,'proxy','websocket_connection_finished',$4,$5,'error','fixture')`, rec2, conn*100+7, now, native, meta); err != nil {
			t.Fatal(err)
		}
		// Historical inferred connection row must disappear after semantic replay.
		if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,recording_id,capture_run_id,project_id,status,processor_version) values($1,$2,$3,$4,'inferred','old')`, "inf:"+parent, rec, run, project); err != nil {
			t.Fatal(err)
		}
	}
	rawHash := func() string {
		var hash string
		if err := db.Pool.QueryRow(ctx, `select md5(string_agg(row_to_json(e)::text,'|' order by e.seq,e.recording_id)) from recording_events e join recordings r on r.id=e.recording_id where r.capture_run_id=$1`, run).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	before := rawHash()
	var previous string
	for repeat := 0; repeat < 2; repeat++ {
		job.InputRef = json.RawMessage(fmt.Sprintf(`{"reprocess":"test-%d"}`, repeat))
		for conn := 0; conn < 2; conn++ {
			if err := d.normalizeAttempt(ctx, job, run, AttemptKey(run, fmt.Sprintf("conn-%d", conn))); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.Resolve(ctx, job); err != nil {
			t.Fatal(err)
		}
		if err := d.Coverage(ctx, job); err != nil {
			t.Fatal(err)
		}
		var calls, connections, inferences, links, completed int
		if err := db.Pool.QueryRow(ctx, `select count(*) filter(where entity_kind='websocket_call'),count(*) filter(where entity_kind='websocket_connection'),count(*) filter(where entity_kind='websocket_call' and terminal_state='completed') from model_attempts where capture_run_id=$1`, run).Scan(&calls, &connections, &completed); err != nil {
			t.Fatal(err)
		}
		if err := db.Pool.QueryRow(ctx, `select count(*) from model_inferences where capture_run_id=$1`, run).Scan(&inferences); err != nil {
			t.Fatal(err)
		}
		if err := db.Pool.QueryRow(ctx, `select count(*) from attempt_event_links where project_id=$1`, project).Scan(&links); err != nil {
			t.Fatal(err)
		}
		if calls != 4 || connections != 2 || completed != 4 || inferences != 4 || links != 12 {
			t.Fatalf("calls=%d conn=%d completed=%d inf=%d links=%d", calls, connections, completed, inferences, links)
		}
		var safeText, safeModel, safeResponseID string
		var nulReplacements int
		if err := db.Pool.QueryRow(ctx, `select response_text,model,projection->>'response_id',(projection->>'postgres_nul_replacements')::int from model_attempts where capture_run_id=$1 and entity_kind='websocket_call' and response_text is not null order by id limit 1`, run).Scan(&safeText, &safeModel, &safeResponseID, &nulReplacements); err != nil {
			t.Fatal(err)
		}
		if safeText != "first\ufffdanswer" || safeModel != "ws\ufffdtest" || safeResponseID != "r1\ufffd" || nulReplacements < 3 {
			t.Fatalf("unsafe or unreported PostgreSQL projection: text=%q model=%q response=%q replacements=%d", safeText, safeModel, safeResponseID, nulReplacements)
		}
		var stale int
		if err := db.Pool.QueryRow(ctx, `select count(*) from model_attempts where capture_run_id=$1 and entity_kind='websocket_connection' and (normalized is not null or usage is not null or inference_id is not null or terminal_state<>'error')`, run).Scan(&stale); err != nil {
			t.Fatal(err)
		}
		if stale != 0 {
			t.Fatal("connection kept aggregated model fields or lost raw terminal")
		}
		var hash string
		if err := db.Pool.QueryRow(ctx, `select md5(string_agg(jsonb_build_array(id,normalized,projection-'evidence_snapshot',evidence_refs)::text,'|' order by id)) from model_attempts where capture_run_id=$1`, run).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		if repeat > 0 && hash != previous {
			t.Fatal("replay not idempotent")
		}
		previous = hash
		var cov Coverage
		var raw json.RawMessage
		if err := db.Pool.QueryRow(ctx, `select coverage from recordings where id=$1`, rec).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &cov); err != nil {
			t.Fatal(err)
		}
		if cov.TransportAttempts != 2 || cov.WebSocketCalls != 4 || cov.UnattributedAttempts != 0 || cov.UnresolvedWebSocketMessages != 0 {
			t.Fatalf("double-counted coverage: %+v", cov)
		}
	}
	if rawHash() != before {
		t.Fatal("raw evidence changed during replay")
	}
	// One child crosses segments. Its exact evidence includes both recordings.
	var refs []EvidenceRef
	var raw json.RawMessage
	if err := db.Pool.QueryRow(ctx, `select evidence_refs from model_attempts where id=$1`, wsCallKey(AttemptKey(run, "conn-0"), 4)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &refs); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].RecordingID != rec || refs[1].RecordingID != rec2 {
		t.Fatalf("cross-segment evidence lost: %+v", refs)
	}
	// Reprocess after an object disappears: keep every raw address, downgrade
	// association, and clear stale successful response/usage projections.
	missing := sha256.Sum256(frames[1].Body)
	key := "ws/" + hex.EncodeToString(missing[:])
	if err := objects.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	job.InputRef = json.RawMessage(`{"reprocess":"missing-object"}`)
	if err := d.normalizeAttempt(ctx, job, run, AttemptKey(run, "conn-0")); err != nil {
		t.Fatal(err)
	}
	if err := d.Resolve(ctx, job); err != nil {
		t.Fatal(err)
	}
	var state string
	var unresolved int
	if err := db.Pool.QueryRow(ctx, `select projection->>'capture_state',(projection->>'unresolved_messages')::int from model_attempts where id=$1`, AttemptKey(run, "conn-0")).Scan(&state, &unresolved); err != nil {
		t.Fatal(err)
	}
	if state != "incomplete" || unresolved == 0 {
		t.Fatal("missing body falsely complete")
	}
	var staleUsage, staleResponse bool
	if err := db.Pool.QueryRow(ctx, `select usage is not null,response is not null from model_inferences where id=$1`, "inf:"+wsCallKey(AttemptKey(run, "conn-0"), 1)).Scan(&staleUsage, &staleResponse); err != nil {
		t.Fatal(err)
	}
	if staleUsage || staleResponse {
		t.Fatal("stale successful usage/response retained after downgrade")
	}
	if err := objects.Put(ctx, key, bytes.NewReader(frames[1].Body), int64(len(frames[1].Body)), "application/json"); err != nil {
		t.Fatal(err)
	}
	// Same generation must retry incomplete captures when a body arrives.
	if err := d.normalizeAttempt(ctx, job, run, AttemptKey(run, "conn-0")); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select projection->>'capture_state' from model_attempts where id=$1`, AttemptKey(run, "conn-0")).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "observed_messages_verified" {
		t.Fatal("recovered blob did not restore projection")
	}
	if rawHash() != before {
		t.Fatal("recovery mutated raw event index")
	}
}
