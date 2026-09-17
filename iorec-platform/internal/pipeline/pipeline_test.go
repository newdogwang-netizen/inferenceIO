package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/jobs"
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
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"ls\\\"}\"}}\n\n",
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

func TestResponsesAPIStateRefs(t *testing.T) {
	n, err := NormalizeRequest("responses", []byte(`{"model":"gpt","previous_response_id":"resp_1","input":[{"type":"function_call_output","call_id":"c1","output":"ok"}],"tools":[{"type":"web_search"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if n.PreviousResponseID != "resp_1" || len(n.ServerStateRefs) != 1 || n.Messages[0].Role != "tool" || n.Messages[0].ToolCallID != "c1" || n.Tools[0] != "web_search" {
		t.Fatalf("unexpected %+v", n)
	}
	prev := &inferenceNode{Norm: &Normalized{APIMode: "responses", ResponseID: "resp_1", MessageHashes: []string{"x"}}}
	ev, ok := linkEvidence(prev, &inferenceNode{Norm: n})
	if !ok || ev.Kind != "response_id_chain" {
		t.Fatalf("want response_id_chain got %+v", ev)
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
