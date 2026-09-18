package pipeline

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func pipelineTestDB(t *testing.T) *store.DB {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
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

func TestAssembleReconstructsOneStreamAcrossRecordingSegments(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-pipeline-segments-" + uuid.NewString()[:8]
	first, second := run+"#0000", run+"#0001"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,segment_no,sequence_base,durable_seq,parsed_seq,state,final_seq) values
		($1,$3,$4,0,0,2,2,'sealed',2), ($2,$3,$4,1,2,4,4,'sealed',4)`, first, second, project, run); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	type eventRow struct {
		recording string
		seq       int64
		event     string
		payload   string
		terminal  *string
	}
	completed := "complete"
	events := []eventRow{
		{first, 1, "attempt_start", `{"method":"POST","url":"https://example.test/v1/chat/completions","api_mode":"chat_completions"}`, nil},
		{first, 2, "inference_request", `{"model":"m","api_mode":"chat_completions","request":{"messages":[{"role":"user","content":"hi"}]}}`, nil},
		{second, 3, "inference_response", `{"response":{"choices":[{"message":{"content":"ok"}}]}}`, nil},
		{second, 4, "attempt_end", `{"status":200}`, &completed},
	}
	for _, event := range events {
		if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,task_id,agent_session_id,inference_id,attempt_id,payload,batch_id,terminal_state) values($1,$2,$2,$3,'proxy',$4,'task-a','session-shared','inference-1','attempt-1',$5::jsonb,$6,$7)`,
			event.recording, event.seq, now.Add(time.Duration(event.seq)*time.Millisecond), event.event, event.payload, fmt.Sprintf("batch-%d", event.seq), event.terminal); err != nil {
			t.Fatal(err)
		}
	}
	input, _ := json.Marshal(batchRef{BatchID: "batch-4", FirstSeq: 3, LastSeq: 4})
	job := &jobs.Job{ProjectID: project, Type: jobs.TypeAssemble, RecordingID: &second, CaptureRunID: &run, InputRef: input, ProcessorVersion: AssemblerVersion}
	if err := (&Deps{DB: db}).Assemble(ctx, job); err != nil {
		t.Fatal(err)
	}
	var attemptRecording, terminal, attemptTask, attemptSession string
	var firstSeq, lastSeq int64
	var startedAt, endedAt *time.Time
	if err := db.Pool.QueryRow(ctx, `select recording_id, terminal_state, task_id, session_id, first_seq, last_seq, started_at, ended_at from model_attempts where id=$1`, AttemptKey(run, "attempt-1")).Scan(&attemptRecording, &terminal, &attemptTask, &attemptSession, &firstSeq, &lastSeq, &startedAt, &endedAt); err != nil {
		t.Fatal(err)
	}
	if attemptRecording != first || terminal != "completed" || attemptTask != "task-a" || attemptSession != "session-shared" || firstSeq != 1 || lastSeq != 4 || startedAt == nil || endedAt == nil {
		t.Fatalf("cross-segment attempt was not reconstructed: rec=%s terminal=%s seq=%d..%d started=%v ended=%v", attemptRecording, terminal, firstSeq, lastSeq, startedAt, endedAt)
	}
	var inferenceRecording, inferenceTask string
	var response, evidence json.RawMessage
	if err := db.Pool.QueryRow(ctx, `select recording_id, task_id, response, evidence_refs from model_inferences where id=$1`, InferenceKey(run, "inference-1")).Scan(&inferenceRecording, &inferenceTask, &response, &evidence); err != nil {
		t.Fatal(err)
	}
	if inferenceRecording != first || inferenceTask != "task-a" || !json.Valid(response) {
		t.Fatalf("cross-segment inference was not reconstructed: rec=%s response=%s", inferenceRecording, response)
	}
	var refs []EvidenceRef
	if err := json.Unmarshal(evidence, &refs); err != nil || len(refs) != 2 || refs[0].RecordingID != first || refs[0].FirstSeq != 2 || refs[1].RecordingID != second || refs[1].LastSeq != 3 {
		t.Fatalf("cross-segment evidence refs are invalid: %s err=%v", evidence, err)
	}
}

func TestHermesHookAttemptKeepsSummaryAndTerminalState(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-hook-attempt-" + uuid.NewString()[:8]
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,durable_seq,parsed_seq,final_seq) values($1,$2,$3,'sealed',2,2,2)`, recording, project, run); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pre := `{"model":"hermes-test","api_mode":"chat_completions","base_url":"http://127.0.0.1:8080/v1","request":{"preview":{"type":"str","length":50000,"prefix":"{truncated"}},"request_messages":[{"role":"system","content":"be helpful"},{"role":"user","content":"say ok"}]}`
	post := `{"model":"hermes-test","api_mode":"chat_completions","response":{"model":"hermes-test","finish_reason":"stop","usage":{"total_tokens":3},"assistant_message":{"role":"assistant","content":"HOOK_OK","tool_calls":[]}}}`
	for i, event := range []struct {
		name, payload, terminal string
	}{{"pre_api_request", pre, ""}, {"post_api_request", post, "complete"}} {
		if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,task_id,agent_session_id,inference_id,attempt_id,payload,batch_id,terminal_state)
			values($1,$2,$2,$3,'hook:hermes',$4,'task-1','session-1','inference-1','attempt-1',$5::jsonb,'batch-1',$6)`,
			recording, i+1, now.Add(time.Duration(i)*time.Millisecond), event.name, event.payload, nilIfEmpty(event.terminal)); err != nil {
			t.Fatal(err)
		}
	}
	input, _ := json.Marshal(batchRef{BatchID: "batch-1", FirstSeq: 1, LastSeq: 2})
	job := &jobs.Job{ProjectID: project, Type: jobs.TypeAssemble, RecordingID: &recording, CaptureRunID: &run, InputRef: input, ProcessorVersion: AssemblerVersion}
	deps := &Deps{DB: db}
	if err := deps.Assemble(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := deps.normalizeAttempt(ctx, job, run, AttemptKey(run, "attempt-1")); err != nil {
		t.Fatal(err)
	}
	if err := deps.normalizeInference(ctx, InferenceKey(run, "inference-1")); err != nil {
		t.Fatal(err)
	}
	var terminal, apiMode, method, model, responseText string
	var normalized json.RawMessage
	if err := db.Pool.QueryRow(ctx, `select terminal_state,api_mode,method,model,response_text,normalized from model_attempts where id=$1`, AttemptKey(run, "attempt-1")).
		Scan(&terminal, &apiMode, &method, &model, &responseText, &normalized); err != nil {
		t.Fatal(err)
	}
	var attempt Normalized
	if err := json.Unmarshal(normalized, &attempt); err != nil {
		t.Fatal(err)
	}
	if terminal != "completed" || apiMode != "chat_completions" || method != "POST" || model != "hermes-test" || responseText != "HOOK_OK" || !attempt.BodyUnavailable || len(attempt.Messages) != 2 {
		t.Fatalf("hook attempt projection is incomplete: terminal=%s api=%s method=%s model=%s response=%q normalized=%s", terminal, apiMode, method, model, responseText, normalized)
	}
	if err := db.Pool.QueryRow(ctx, `select normalized from model_inferences where id=$1`, InferenceKey(run, "inference-1")).Scan(&normalized); err != nil {
		t.Fatal(err)
	}
	var inference Normalized
	if err := json.Unmarshal(normalized, &inference); err != nil {
		t.Fatal(err)
	}
	if !inference.BodyUnavailable || len(inference.Messages) != 2 || inference.ResponseText != "HOOK_OK" {
		t.Fatalf("hook inference summary was not retained honestly: %s", normalized)
	}

	// The recorder can later emit a bounded cross-source correlation from the
	// hook-native inference to the transport-native inference. Resolve must use
	// the transport ID as the stable URL, keep the hook request/response, and
	// point both observations at one inference.
	proxyNativeInference := "proxy-inference-1"
	proxyInference := InferenceKey(run, proxyNativeInference)
	proxyNativeAttempt := "proxy-attempt-1"
	proxyAttempt := AttemptKey(run, proxyNativeAttempt)
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,inference_id,attempt_id,payload,batch_id)
		values($1,3,3,$2,'proxy','logical_inference_request',$3,$4,'{"path":"/v1/chat/completions","summary":{"model":"hermes-test"}}','batch-2'),
		($1,4,4,$2,'correlation','inference_correlation',$3,null,$5::jsonb,'batch-2')`,
		recording, now.Add(2*time.Millisecond), proxyNativeInference, proxyNativeAttempt,
		fmt.Sprintf(`{"method":"unique_temporal_candidate","native_inference_id":%q}`, "inference-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `update recording_events set confidence=0.9 where recording_id=$1 and seq=4`, recording); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,agent_session_id,inference_id,payload,confidence,batch_id)
		values($1,5,5,$2,'correlation','inference_correlation','session-1',$3,'{"method":"exact_transport_session_id","transport_sequence":3}',0.8,'batch-2')`, recording, now.Add(3*time.Millisecond), proxyNativeInference); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `update recordings set durable_seq=5,parsed_seq=5,final_seq=5 where id=$1`, recording); err != nil {
		t.Fatal(err)
	}
	complete := attempt
	complete.BodyUnavailable = false
	completeJSON, _ := json.Marshal(complete)
	fingerprint, _ := hex.DecodeString(complete.Fingerprint)
	inputHash, _ := hex.DecodeString(complete.InputHash)
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,inference_id,source,api_mode,model,started_at,ended_at,terminal_state,status_code,response_text,normalized,request_fingerprint,input_hash,first_seq,last_seq,processor_version)
		values($1,$2,$3,$4,$5,$6,'proxy','chat_completions','hermes-test',$7,$8,'completed',200,'HOOK_OK',$9,$10,$11,3,3,'test')`,
		proxyAttempt, proxyNativeAttempt, recording, project, run, proxyInference, now.Add(2*time.Millisecond), now.Add(3*time.Millisecond), completeJSON, fingerprint, inputHash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,native_id,recording_id,capture_run_id,project_id,status,first_attempt_at,evidence_refs,processor_version)
		values($1,$2,$3,$4,$5,'observed',$6,'[]','test')`, proxyInference, proxyNativeInference, recording, run, project, now.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	resolveJob := &jobs.Job{ProjectID: project, Type: jobs.TypeResolve, CaptureRunID: &run, ProcessorVersion: ResolverVersion}
	if err := deps.Resolve(ctx, resolveJob); err != nil {
		t.Fatal(err)
	}
	var attemptCount int
	var taskID, sessionID string
	var request, response, canonicalNormalized json.RawMessage
	if err := db.Pool.QueryRow(ctx, `select attempt_count,task_id,session_id,request,response,normalized from model_inferences where id=$1`, proxyInference).
		Scan(&attemptCount, &taskID, &sessionID, &request, &response, &canonicalNormalized); err != nil {
		t.Fatal(err)
	}
	if attemptCount != 2 || taskID != TaskKey(run, "agent_task", "task-1") || sessionID != SessionKey(run, "session-1") || len(request) == 0 || len(response) == 0 {
		t.Fatalf("correlated inference lost evidence: attempts=%d task=%q session=%q request=%s response=%s", attemptCount, taskID, sessionID, request, response)
	}
	var canonical Normalized
	if err := json.Unmarshal(canonicalNormalized, &canonical); err != nil {
		t.Fatal(err)
	}
	if canonical.BodyUnavailable || canonical.ResponseText != "HOOK_OK" {
		t.Fatalf("correlated inference did not select the complete transport projection: %s", canonicalNormalized)
	}
	var aliasRows, canonicalAttempts int
	if err := db.Pool.QueryRow(ctx, `select count(*) from model_inferences where id=$1`, InferenceKey(run, "inference-1")).Scan(&aliasRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select count(*) from model_attempts where id in ($1,$2) and inference_id=$3`, AttemptKey(run, "attempt-1"), proxyAttempt, proxyInference).Scan(&canonicalAttempts); err != nil {
		t.Fatal(err)
	}
	if aliasRows != 0 || canonicalAttempts != 2 {
		t.Fatalf("cross-source alias was not canonicalized: alias_rows=%d canonical_attempts=%d", aliasRows, canonicalAttempts)
	}
	var relationStatus string
	var relationConfidence float64
	if err := db.Pool.QueryRow(ctx, `select status,confidence from relations where capture_run_id=$1 and type='attempt_of' and from_id=$2 and to_id=$3 and superseded_by is null`, run, AttemptKey(run, "attempt-1"), proxyInference).Scan(&relationStatus, &relationConfidence); err != nil {
		t.Fatal(err)
	}
	if relationStatus != "inferred" || math.Abs(relationConfidence-0.9) > 1e-6 {
		t.Fatalf("cross-source confidence was not preserved: status=%s confidence=%v", relationStatus, relationConfidence)
	}
	coverageJob := &jobs.Job{ProjectID: project, Type: jobs.TypeCoverage, RecordingID: &recording, CaptureRunID: &run, ProcessorVersion: CoverageVersion}
	if err := deps.Coverage(ctx, coverageJob); err != nil {
		t.Fatal(err)
	}
	var coverageJSON json.RawMessage
	if err := db.Pool.QueryRow(ctx, `select coverage from recordings where id=$1`, recording).Scan(&coverageJSON); err != nil {
		t.Fatal(err)
	}
	var coverage Coverage
	if err := json.Unmarshal(coverageJSON, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.TransportAttempts != 1 || coverage.BodyUnavailable != 0 || !coverage.AllAttemptsHaveTerminalState {
		t.Fatalf("observer evidence polluted transport coverage: %+v", coverage)
	}
	rulesJob := &jobs.Job{ProjectID: project, Type: jobs.TypeRules, CaptureRunID: &run, ProcessorVersion: RulesVersion}
	if err := deps.Rules(ctx, rulesJob); err != nil {
		t.Fatal(err)
	}
	var bodyFindings int
	if err := db.Pool.QueryRow(ctx, `select count(*) from findings where capture_run_id=$1 and rule_id='model_body_unavailable' and status='open'`, run).Scan(&bodyFindings); err != nil {
		t.Fatal(err)
	}
	if bodyFindings != 0 {
		t.Fatalf("complete correlated transport body still produced %d body findings", bodyFindings)
	}
}

func TestCaptureTaskIndexSplitsInterleavedTasksAndSessionFallbackAcrossSegments(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-task-split-" + uuid.NewString()[:8]
	first, second := run+"#0000", run+"#0001"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,segment_no,sequence_base,durable_seq,parsed_seq,state) values
		($1,$3,$4,0,0,3,3,'sealed'), ($2,$3,$4,1,3,6,6,'sealed')`, first, second, project, run); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	type taskEvent struct {
		recording, task, session string
		seq                      int64
	}
	events := []taskEvent{
		{first, "cron-a", "shared", 1},
		{first, "message-b", "shared", 2},
		{first, "cron-a", "shared", 3},
		{second, "message-b", "shared", 4},
		{second, "", "session-only", 5},
		{second, "cron-a", "shared", 6},
	}
	for _, event := range events {
		if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,task_id,agent_session_id,payload,batch_id)
			values($1,$2,$2,$3,'hook:hermes','pre_api_request',$4,$5,'{}'::jsonb,$6)`,
			event.recording, event.seq, now.Add(time.Duration(event.seq)*time.Millisecond), nilIfEmpty(event.task), event.session, fmt.Sprintf("task-batch-%d", event.seq)); err != nil {
			t.Fatal(err)
		}
	}
	deps := &Deps{DB: db}
	if err := deps.rebuildCaptureTasks(ctx, project, run); err != nil {
		t.Fatal(err)
	}
	if err := deps.rebuildCaptureTasks(ctx, project, run); err != nil {
		t.Fatalf("idempotent rebuild failed: %v", err)
	}
	rows, err := db.Pool.Query(ctx, `select id,split_policy,boundary_kind,native_id,session_ids,event_count,first_seq,last_seq from capture_tasks where capture_run_id=$1 order by first_seq`, run)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type gotTask struct {
		id, policy, kind, native string
		sessions                 json.RawMessage
		count, first, last       int64
	}
	var got []gotTask
	for rows.Next() {
		var task gotTask
		if err := rows.Scan(&task.id, &task.policy, &task.kind, &task.native, &task.sessions, &task.count, &task.first, &task.last); err != nil {
			t.Fatal(err)
		}
		got = append(got, task)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected three logical tasks, got %+v", got)
	}
	if got[0].id != TaskKey(run, "agent_task", "cron-a") || got[0].policy != taskSplitPolicyV1 || got[0].kind != "agent_task" || got[0].count != 3 || got[0].first != 1 || got[0].last != 6 || string(got[0].sessions) != `["shared"]` {
		t.Fatalf("cron task was not reconstructed: %+v", got[0])
	}
	if got[1].native != "message-b" || got[1].count != 2 || got[1].first != 2 || got[1].last != 4 {
		t.Fatalf("message task was not reconstructed: %+v", got[1])
	}
	if got[2].kind != "agent_session" || got[2].native != "session-only" || got[2].count != 1 || got[2].first != 5 || got[2].last != 5 {
		t.Fatalf("session fallback was not reconstructed: %+v", got[2])
	}
}

func TestResolvePromotesNativeTaskIDToStableCaptureTaskKey(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-task-resolve-" + uuid.NewString()[:8]
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state) values($1,$2,$3,'sealed')`, recording, project, run); err != nil {
		t.Fatal(err)
	}
	inference := InferenceKey(run, "inference-1")
	fallbackInference := InferenceKey(run, "inference-session-fallback")
	if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,native_id,recording_id,capture_run_id,project_id,status,first_attempt_at,task_id,session_id,evidence_refs,processor_version)
		values
			($1,'inference-1',$3,$4,$5,'observed',now(),'cron-a','shared','[]','test'),
			($2,'inference-session-fallback',$3,$4,$5,'observed',now(),null,'session-only','[]','test')`, inference, fallbackInference, recording, run, project); err != nil {
		t.Fatal(err)
	}
	job := &jobs.Job{ProjectID: project, Type: jobs.TypeResolve, RecordingID: &recording, CaptureRunID: &run, ProcessorVersion: ResolverVersion}
	deps := &Deps{DB: db}
	if err := deps.Resolve(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := deps.Resolve(ctx, job); err != nil {
		t.Fatalf("second resolve changed task identity: %v", err)
	}
	var taskID, sessionID string
	if err := db.Pool.QueryRow(ctx, `select task_id,session_id from model_inferences where id=$1`, inference).Scan(&taskID, &sessionID); err != nil {
		t.Fatal(err)
	}
	if taskID != TaskKey(run, "agent_task", "cron-a") || sessionID != SessionKey(run, "shared") {
		t.Fatalf("resolved task/session keys are wrong: task=%q session=%q", taskID, sessionID)
	}
	if err := db.Pool.QueryRow(ctx, `select task_id,session_id from model_inferences where id=$1`, fallbackInference).Scan(&taskID, &sessionID); err != nil {
		t.Fatal(err)
	}
	if taskID != TaskKey(run, "agent_session", "session-only") || sessionID != SessionKey(run, "session-only") {
		t.Fatalf("session fallback changed across resolve passes: task=%q session=%q", taskID, sessionID)
	}
}

func TestResolvePersistsRawEvidenceForInferredRelations(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-relation-evidence-" + uuid.NewString()[:8]
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,durable_seq,parsed_seq,final_seq) values($1,$2,$3,'sealed',4,4,4)`, recording, project, run); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	type relationFixture struct {
		nativeID, sessionID, fingerprint string
		at                               time.Time
		seq                              int64
		messages                         []string
	}
	fixtures := []relationFixture{
		{"parent-1", "parent-session", "aa", now, 1, []string{"parent-1"}},
		{"child-1", "child-session", "bb", now.Add(time.Second), 2, []string{"child-1"}},
		{"child-2", "child-session", "bb", now.Add(2 * time.Second), 3, []string{"child-1", "child-2"}},
		{"parent-2", "parent-session", "aa", now.Add(3 * time.Second), 4, []string{"parent-1", "parent-2"}},
	}
	for _, fixture := range fixtures {
		norm, err := json.Marshal(Normalized{
			APIMode:       "chat_completions",
			Fingerprint:   fixture.fingerprint,
			MessageHashes: fixture.messages,
		})
		if err != nil {
			t.Fatal(err)
		}
		refs, err := json.Marshal([]EvidenceRef{{RecordingID: recording, FirstSeq: fixture.seq, LastSeq: fixture.seq}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,native_id,recording_id,capture_run_id,project_id,status,first_attempt_at,api_mode,request_fingerprint,normalized,session_id,pid,evidence_refs,processor_version)
			values($1,$2,$3,$4,$5,'observed',$6,'chat_completions',decode($7,'hex'),$8,$9,42,$10,'test')`,
			InferenceKey(run, fixture.nativeID), fixture.nativeID, recording, run, project, fixture.at, fixture.fingerprint, norm, fixture.sessionID, refs); err != nil {
			t.Fatal(err)
		}
	}

	job := &jobs.Job{ProjectID: project, Type: jobs.TypeResolve, RecordingID: &recording, CaptureRunID: &run, ProcessorVersion: ResolverVersion}
	if err := (&Deps{DB: db}).Resolve(ctx, job); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool.Query(ctx, `select type,evidence from relations where capture_run_id=$1 and type in ('follows','parent_of') and superseded_by is null order by type,from_id`, run)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var relationType string
		var raw json.RawMessage
		if err := rows.Scan(&relationType, &raw); err != nil {
			t.Fatal(err)
		}
		var evidenceChain []evidence
		if err := json.Unmarshal(raw, &evidenceChain); err != nil {
			t.Fatalf("%s relation has invalid evidence JSON %s: %v", relationType, raw, err)
		}
		if len(evidenceChain) != 1 || len(evidenceChain[0].Refs) == 0 {
			t.Fatalf("%s relation is not traceable to raw recording evidence: %s", relationType, raw)
		}
		for _, ref := range evidenceChain[0].Refs {
			if ref.RecordingID != recording || ref.FirstSeq < 1 || ref.LastSeq > 4 || ref.FirstSeq > ref.LastSeq {
				t.Fatalf("%s relation has invalid raw evidence ref: %+v", relationType, ref)
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("expected two follows and one inferred parent_of relation, got %d", count)
	}
}

func TestStableTaskIdentityRejectsCrossTaskEvidence(t *testing.T) {
	current := "task-a"
	if err := mergeStableIdentity(&current, "", "task"); err != nil || current != "task-a" {
		t.Fatalf("empty evidence changed identity: current=%q err=%v", current, err)
	}
	if err := mergeStableIdentity(&current, "task-a", "task"); err != nil {
		t.Fatalf("matching identity was rejected: %v", err)
	}
	if err := mergeStableIdentity(&current, "task-b", "task"); err == nil {
		t.Fatal("cross-task evidence was silently merged")
	}
}

func TestMergeEgressCountFailsClosedAndUsesMaximumEvidence(t *testing.T) {
	c := Coverage{}
	mergeEgressCount(&c, "auth", 3)
	mergeEgressCount(&c, "auth", 1)
	mergeEgressCount(&c, "invented-safe-class", 2)
	mergeEgressCount(&c, "telemetry", -1)
	if c.ObservedEgressClasses["auth"] != 3 {
		t.Fatalf("expected maximum auth evidence, got %+v", c.ObservedEgressClasses)
	}
	if c.ObservedEgressClasses["unknown_external"] != 2 {
		t.Fatalf("unknown class did not fail closed: %+v", c.ObservedEgressClasses)
	}
	if c.ObservedEgressClasses["telemetry"] != 0 {
		t.Fatalf("negative counts must clamp to zero: %+v", c.ObservedEgressClasses)
	}
}

func TestCoverageClaimRequiresPlatformOwnedTransportProof(t *testing.T) {
	clean := Coverage{
		CollectorClaim:               "best-effort",
		CapabilitiesKnown:            true,
		AllAttemptsHaveTerminalState: true,
		TransportAttempts:            1,
	}
	assignCoverageClaim(&clean, "sealed")
	if clean.Claim != "best-effort" {
		t.Fatalf("zero counters without platform proof must remain best-effort, got %q", clean.Claim)
	}
	if len(clean.KnownGaps) != 1 {
		t.Fatalf("missing transport proof must be explicit: %+v", clean.KnownGaps)
	}

	clean.PlatformTransportProofVerified = true
	assignCoverageClaim(&clean, "sealed")
	if clean.Claim != "client-complete" {
		t.Fatalf("verified clean client evidence should be client-complete, got %q", clean.Claim)
	}

	clean.UnknownEgress = 1
	assignCoverageClaim(&clean, "sealed")
	if clean.Claim != "best-effort" {
		t.Fatalf("verified transport with unknown egress must downgrade, got %q", clean.Claim)
	}

	clean.UnknownEgress = 0
	clean.CollectorClaim = "unknown"
	assignCoverageClaim(&clean, "sealed")
	if clean.Claim != "unknown" {
		t.Fatalf("collector unknown must remain unknown, got %q", clean.Claim)
	}
}

func TestMissingResponseProjectionRuleOnlyFlagsSuccessfulModelOutput(t *testing.T) {
	statusOK, statusError := 200, 500
	empty, text := "", "done"
	if !responseProjectionMissing("chat_completions", &statusOK, "completed", &empty, 0) {
		t.Fatal("successful model response without text or tools was not flagged")
	}
	for name, missing := range map[string]bool{
		"text":        responseProjectionMissing("chat_completions", &statusOK, "completed", &text, 0),
		"tool call":   responseProjectionMissing("chat_completions", &statusOK, "completed", &empty, 1),
		"http error":  responseProjectionMissing("chat_completions", &statusError, "error", &empty, 0),
		"non-model":   responseProjectionMissing("unknown", &statusOK, "completed", &empty, 0),
		"no terminal": responseProjectionMissing("chat_completions", &statusOK, "unknown", &empty, 0),
	} {
		if missing {
			t.Fatalf("%s was incorrectly flagged as a missing response projection", name)
		}
	}
}

func TestDuplicateRequestFindingIsScopedToCaptureRun(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}

	runs := []string{"run-duplicate-a-" + uuid.NewString()[:8], "run-duplicate-b-" + uuid.NewString()[:8]}
	for _, run := range runs {
		recording := run + "#0000"
		if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,durable_seq,parsed_seq,final_seq,coverage) values($1,$2,$3,'sealed',2,2,2,'{}')`, recording, project, run); err != nil {
			t.Fatal(err)
		}
		for index := 1; index <= 2; index++ {
			nativeID := fmt.Sprintf("inference-%d", index)
			if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,native_id,recording_id,capture_run_id,project_id,status,first_attempt_at,input_hash,evidence_refs,processor_version)
				values($1,$2,$3,$4,$5,'observed',now()+($6 * interval '1 second'),decode('aa','hex'),$7,'test')`,
				InferenceKey(run, nativeID), nativeID, recording, run, project, index,
				fmt.Sprintf(`[{"recording_id":%q,"first_seq":%d,"last_seq":%d}]`, recording, index, index)); err != nil {
				t.Fatal(err)
			}
		}
	}

	deps := &Deps{DB: db}
	// Re-run the first capture after the second one to prove that identical
	// input hashes cannot overwrite or move a finding between capture runs.
	for _, run := range []string{runs[0], runs[1], runs[0]} {
		if err := deps.Rules(ctx, &jobs.Job{ProjectID: project, Type: jobs.TypeRules, CaptureRunID: &run, ProcessorVersion: RulesVersion}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Pool.Query(ctx, `select capture_run_id,recording_id,evidence_key,detail,evidence_refs from findings where project_id=$1 and rule_id='duplicate_request' and status='open' order by capture_run_id`, project)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var captureRun, recording, evidenceKey string
		var detail, rawEvidence json.RawMessage
		if err := rows.Scan(&captureRun, &recording, &evidenceKey, &detail, &rawEvidence); err != nil {
			t.Fatal(err)
		}
		if count >= len(runs) {
			t.Fatalf("unexpected extra duplicate finding for capture %q", captureRun)
		}
		if captureRun != runs[count] || recording != captureRun+"#0000" || !strings.HasPrefix(evidenceKey, captureRun+"#") {
			t.Fatalf("duplicate finding crossed capture boundary: run=%q recording=%q key=%q", captureRun, recording, evidenceKey)
		}
		var decoded struct {
			InferenceIDs []string `json:"inference_ids"`
		}
		if err := json.Unmarshal(detail, &decoded); err != nil || len(decoded.InferenceIDs) != 2 {
			t.Fatalf("invalid duplicate finding detail %s: %v", detail, err)
		}
		for _, id := range decoded.InferenceIDs {
			if !strings.HasPrefix(id, captureRun+"~") {
				t.Fatalf("finding for %q contains inference from another capture: %q", captureRun, id)
			}
		}
		var refs []EvidenceRef
		if err := json.Unmarshal(rawEvidence, &refs); err != nil || len(refs) != 2 || refs[0].FirstSeq != 1 || refs[1].FirstSeq != 2 {
			t.Fatalf("duplicate finding did not preserve inference evidence: %s err=%v", rawEvidence, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != len(runs) {
		t.Fatalf("expected one duplicate finding per capture run, got %d", count)
	}
}

func TestNormalizeChatCompletionsAndPrefixChain(t *testing.T) {
	req1 := `{"model":"m","stream":true,"messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"terminal"}}]}`
	req2 := `{"model":"m","stream":true,"messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"},{"role":"assistant","content":"hello"},{"role":"user","content":"more"}],"tools":[{"type":"function","function":{"name":"terminal"}}]}`
	a, err := NormalizeRequest("chat_completions", []byte(req1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NormalizeRequest("chat_completions", []byte(req2))
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatal("same system+tools must share fingerprint")
	}
	if a.InputHash == b.InputHash {
		t.Fatal("different inputs must differ")
	}
	if !isPrefix(a.MessageHashes, b.MessageHashes) {
		t.Fatal("expected prefix chain")
	}
	ev, ok := linkEvidence(&inferenceNode{Norm: a}, &inferenceNode{Norm: b})
	if !ok || ev.Kind != "prefix_chain" {
		t.Fatalf("want prefix_chain got %+v %v", ev, ok)
	}
	d := ComputeInputDiff("a", "b", a, b)
	if d.Messages["added"] != 2 || d.Messages["unchanged"] != 2 || d.SystemPromptChanged {
		t.Fatalf("bad diff %+v", d)
	}
}

func TestApplyStreamOpenAI(t *testing.T) {
	n := &Normalized{APIMode: "chat_completions"}
	chunks := []string{
		"data: {\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\n",
	}
	ApplyStream(n, chunks)
	if n.ResponseText != "Hello" || n.FinishReason != "stop" || n.StreamTerminated == nil || *n.StreamTerminated {
		t.Fatalf("unexpected %+v", n)
	}
	ApplyStream(n, append(chunks, "data: [DONE]\n\n"))
	if !*n.StreamTerminated || n.Usage["prompt_tokens"].(float64) != 10 {
		t.Fatalf("expected terminated with usage: %+v", n)
	}
}

func TestApplyStreamAnthropicToolUse(t *testing.T) {
	n := &Normalized{APIMode: "anthropic_messages"}
	chunks := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude\",\"usage\":{\"input_tokens\":5}}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"ls\\\"}\"}}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":7}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	ApplyStream(n, chunks)
	if len(n.ResponseToolCalls) != 1 || n.ResponseToolCalls[0].Name != "bash" || n.ResponseToolCalls[0].ID != "toolu_1" || n.FinishReason != "tool_use" || !*n.StreamTerminated {
		b, _ := json.Marshal(n)
		t.Fatalf("unexpected %s", b)
	}
	if n.Usage["input_tokens"].(float64) != 5 || n.Usage["output_tokens"].(float64) != 7 {
		t.Fatalf("usage not merged: %v", n.Usage)
	}
}

func TestDecodeGzipSSEAndHermesObserverResponse(t *testing.T) {
	raw := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"IOREC_CLAUDE_OK\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeContentEncoding(compressed.Bytes(), "gzip")
	if err != nil {
		t.Fatal(err)
	}
	n := &Normalized{APIMode: "anthropic_messages"}
	ApplyStream(n, []string{string(decoded)})
	if n.ResponseText != "IOREC_CLAUDE_OK" || n.StreamTerminated == nil || !*n.StreamTerminated {
		t.Fatalf("gzip SSE response was not normalized: %+v", n)
	}

	hermes := &Normalized{APIMode: "chat_completions"}
	ApplyResponseBody(hermes, []byte(`{"model":"m","finish_reason":"stop","usage":{"total_tokens":3},"assistant_message":{"role":"assistant","content":"IOREC_HERMES_OK","tool_calls":[]}}`))
	if hermes.ResponseText != "IOREC_HERMES_OK" || hermes.FinishReason != "stop" || hermes.Model != "m" || hermes.Usage["total_tokens"].(float64) != 3 {
		t.Fatalf("Hermes observer response was not normalized: %+v", hermes)
	}
	if requestBodyExpected("unknown", "GET", nil) || !requestBodyExpected("chat_completions", "POST", nil) || !requestBodyExpected("unknown", "POST", nil) {
		t.Fatal("request body expectation misclassified bodyless or model requests")
	}
}

func TestNormalizeAttemptReassemblesChunkedCompressedBodies(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-chunked-body-" + uuid.NewString()[:8]
	recording := run + "#0000"
	nativeAttempt := "attempt-1"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state) values($1,$2,$3,'sealed')`, recording, project, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,url,api_mode,terminal_state,status_code,response_headers,sse_event_count,processor_version)
		values($1,$2,$3,$4,$5,'proxy','https://api.anthropic.com/v1/messages','anthropic_messages','truncated',200,'{"content-type":["text/event-stream"],"content-encoding":["gzip"]}',2,'test')`,
		AttemptKey(run, nativeAttempt), nativeAttempt, recording, project, run); err != nil {
		t.Fatal(err)
	}
	store, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	deps := &Deps{DB: db, Obj: store}
	putBlob := func(body []byte, mediaType string) []byte {
		digest := sha256.Sum256(body)
		hexDigest := hex.EncodeToString(digest[:])
		key := objstore.BlobKey(tenant.String(), project.String(), hexDigest)
		if err := store.Put(ctx, key, bytes.NewReader(body), int64(len(body)), mediaType); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `insert into blobs(project_id,sha256,size,media_type,object_key,state) values($1,$2,$3,$4,$5,'active')`, project, digest[:], len(body), mediaType, key); err != nil {
			t.Fatal(err)
		}
		return digest[:]
	}
	request := []byte(`{"model":"claude-test","stream":true,"messages":[{"role":"user","content":"hello"}]}`)
	response := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"chunked response\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	var gzipResponse bytes.Buffer
	zw := gzip.NewWriter(&gzipResponse)
	if _, err := zw.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	type bodyPart struct {
		event, media string
		sequence     int
		body         []byte
	}
	parts := []bodyPart{
		{protocol.EvRequestBodyChunk, "application/json", 1, request[:31]},
		{protocol.EvRequestBodyChunk, "application/json", 2, request[31:]},
		{protocol.EvResponseBodyChunk, "text/event-stream", 1, gzipResponse.Bytes()[:17]},
		{protocol.EvResponseBodyChunk, "text/event-stream", 2, gzipResponse.Bytes()[17:]},
		{protocol.EvResponseBodyChunk, "", 3, nil},
	}
	now := time.Now().UTC()
	for index, part := range parts {
		sum := sha256.Sum256(part.body)
		payload, _ := json.Marshal(map[string]any{"chunk_sequence": part.sequence, "captured_size": len(part.body), "observed_size": len(part.body), "sha256": "sha256:" + hex.EncodeToString(sum[:])})
		var digest []byte
		var size *int
		if len(part.body) > 0 {
			digest = putBlob(part.body, part.media)
			bodySize := len(part.body)
			size = &bodySize
		}
		if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,payload_sha256,payload_size,raw_media_type,batch_id)
			values($1,$2,$2,$3,'proxy',$4,$5,$6,$7,$8,$9,$10)`, recording, index+1, now.Add(time.Duration(index)*time.Millisecond), part.event, nativeAttempt, payload, digest, size, nilIfEmpty(part.media), fmt.Sprintf("batch-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	job := &jobs.Job{ProjectID: project, RecordingID: &recording, CaptureRunID: &run}
	if err := deps.normalizeAttempt(ctx, job, run, AttemptKey(run, nativeAttempt)); err != nil {
		t.Fatal(err)
	}
	var normalized json.RawMessage
	var responseText, terminal string
	if err := db.Pool.QueryRow(ctx, `select normalized,response_text,terminal_state from model_attempts where id=$1`, AttemptKey(run, nativeAttempt)).Scan(&normalized, &responseText, &terminal); err != nil {
		t.Fatal(err)
	}
	var got Normalized
	if err := json.Unmarshal(normalized, &got); err != nil {
		t.Fatal(err)
	}
	if got.BodyUnavailable || len(got.Messages) != 1 || got.Messages[0].Text != "hello" || responseText != "chunked response" || terminal != "completed" || got.StreamTerminated == nil || !*got.StreamTerminated {
		t.Fatalf("chunked bodies were not reconstructed: normalized=%s response=%q terminal=%q", normalized, responseText, terminal)
	}
}

func TestResponsesAPIStateRefs(t *testing.T) {
	n, err := NormalizeRequest("responses", []byte(`{"model":"gpt","previous_response_id":"resp_1","input":[{"type":"function_call_output","call_id":"c1","output":"ok"}],"tools":[{"type":"web_search"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if n.PreviousResponseID != "resp_1" || len(n.ServerStateRefs) != 1 || n.Messages[0].Role != "tool" || n.Messages[0].ToolCallID != "c1" || n.Tools[0] != "web_search" {
		t.Fatalf("unexpected %+v", n)
	}
	prevRef := EvidenceRef{RecordingID: "recording-1", FirstSeq: 1, LastSeq: 2}
	curRef := EvidenceRef{RecordingID: "recording-1", FirstSeq: 3, LastSeq: 4}
	prev := &inferenceNode{Norm: &Normalized{APIMode: "responses", ResponseID: "resp_1", MessageHashes: []string{"x"}}, Evidence: []EvidenceRef{prevRef}}
	ev, ok := linkEvidence(prev, &inferenceNode{Norm: n, Evidence: []EvidenceRef{prevRef, curRef}})
	if !ok || ev.Kind != "response_id_chain" {
		t.Fatalf("want response_id_chain got %+v", ev)
	}
	if len(ev.Refs) != 2 || ev.Refs[0] != prevRef || ev.Refs[1] != curRef {
		t.Fatalf("relationship evidence refs were not preserved and deduplicated: %+v", ev.Refs)
	}
}

func TestDetectAPIMode(t *testing.T) {
	cases := map[string]string{
		"https://api.openai.com/v1/chat/completions":                                           "chat_completions",
		"https://api.anthropic.com/v1/messages":                                                "anthropic_messages",
		"https://generativelanguage.googleapis.com/v1beta/models/gemini:streamGenerateContent": "gemini_generate",
		"https://chatgpt.com/backend-api/codex/responses":                                      "responses",
		"https://example.com/other":                                                            "unknown",
	}
	for u, want := range cases {
		if got := detectAPIMode(u); got != want {
			t.Errorf("%s: want %s got %s", u, want, got)
		}
	}
}
