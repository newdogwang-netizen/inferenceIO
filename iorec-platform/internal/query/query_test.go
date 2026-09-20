package query

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func queryTestDB(t *testing.T) *store.DB {
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

func queryProject(t *testing.T, db *store.DB) auth.Principal {
	tenant, project := uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(context.Background(), `insert into tenants(id,name) values($1,$2)`, tenant, "query-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into projects(id,tenant_id,name) values($1,$2,$3)`, project, tenant, "query-"+project.String()[:8]); err != nil {
		t.Fatal(err)
	}
	return auth.Principal{Kind: auth.KindUser, TenantID: tenant, ProjectID: project, Subject: "query@test", Role: auth.RoleViewer}
}

func requestWithID(t *testing.T, principal auth.Principal, id string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/sessions/"+id, nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
	return req.WithContext(auth.WithPrincipal(ctx, principal))
}

func TestEncodedInferenceIDAndScalarMessagesAreReadable(t *testing.T) {
	db := queryTestDB(t)
	service := &Service{DB: db}
	principal := queryProject(t, db)
	ctx := context.Background()
	run := "run-query-real-" + uuid.NewString()[:8]
	recording := run + "#0000"
	inference := "inf:" + run + "~attempt-1"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, principal.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,coverage) values($1,$2,$3,'sealed','{}')`, recording, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,recording_id,capture_run_id,project_id,status,normalized,processor_version) values($1,$2,$3,$4,'inferred','{"messages":null}','test')`, inference, recording, run, principal.ProjectID); err != nil {
		t.Fatal(err)
	}

	encodedRequest := requestWithID(t, principal, url.PathEscape(inference))
	inferenceResponse := httptest.NewRecorder()
	service.GetInference(inferenceResponse, encodedRequest)
	if inferenceResponse.Code != http.StatusOK {
		t.Fatalf("encoded inference status=%d body=%s", inferenceResponse.Code, inferenceResponse.Body.String())
	}

	timelineResponse := httptest.NewRecorder()
	service.Timeline(timelineResponse, requestWithID(t, principal, recording))
	if timelineResponse.Code != http.StatusOK {
		t.Fatalf("scalar messages timeline status=%d body=%s", timelineResponse.Code, timelineResponse.Body.String())
	}
	var body struct {
		Inferences []struct {
			MessageCount int64 `json:"message_count"`
		} `json:"inferences"`
	}
	if err := json.Unmarshal(timelineResponse.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Inferences) != 1 || body.Inferences[0].MessageCount != 0 {
		t.Fatalf("unexpected scalar message count: %#v", body.Inferences)
	}
}

func TestRecordingTokenTotalsUseOnlyModelCallsAndExposeCoverage(t *testing.T) {
	db := queryTestDB(t)
	service := &Service{DB: db}
	principal := queryProject(t, db)
	ctx := context.Background()
	run := "run-query-tokens-" + uuid.NewString()[:8]
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, principal.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state) values($1,$2,$3,'sealed')`, recording, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,api_mode,entity_kind,usage,processor_version) values
		($1,'native-1',$7,$8,$9,'proxy','responses','request','{"input_tokens":10,"output_tokens":5}','test'),
		($2,'native-2',$7,$8,$9,'proxy','chat_completions','request','{"prompt_tokens":20,"completion_tokens":7}','test'),
		($3,'native-3',$7,$8,$9,'proxy','gemini_generate','request','{"promptTokenCount":3,"candidatesTokenCount":4}','test'),
		($4,'native-4',$7,$8,$9,'proxy','anthropic_messages','request','{"input_tokens":2,"output_tokens":-3}','test'),
		($5,'native-5',$7,$8,$9,'proxy','responses','request','{"total_tokens":99}','test'),
		($6,'native-parent',$7,$8,$9,'proxy','responses','websocket_connection','{"input_tokens":900,"output_tokens":900}','test'),
		($10,'native-hook',$7,$8,$9,'hook:hermes','responses','request','{"input_tokens":800,"output_tokens":800}','test')`,
		"attempt-1-"+run, "attempt-2-"+run, "attempt-3-"+run, "attempt-4-"+run, "attempt-5-"+run,
		"parent-"+run, recording, principal.ProjectID, run, "hook-"+run); err != nil {
		t.Fatal(err)
	}

	type usageSummary struct {
		ModelCalls       int64  `json:"model_call_count"`
		InputTokens      *int64 `json:"input_token_count"`
		InputTokenCalls  int64  `json:"input_token_call_count"`
		OutputTokens     *int64 `json:"output_token_count"`
		OutputTokenCalls int64  `json:"output_token_call_count"`
	}
	assertUsage := func(label string, got usageSummary) {
		t.Helper()
		if got.ModelCalls != 5 || got.InputTokens == nil || *got.InputTokens != 35 || got.InputTokenCalls != 4 ||
			got.OutputTokens == nil || *got.OutputTokens != 16 || got.OutputTokenCalls != 3 {
			t.Fatalf("%s token summary is wrong: %#v", label, got)
		}
	}

	listResponse := httptest.NewRecorder()
	service.ListRecordings(listResponse, httptest.NewRequest(http.MethodGet, "/v1/recordings", nil).WithContext(auth.WithPrincipal(ctx, principal)))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var listBody struct {
		Items []usageSummary `json:"items"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listBody); err != nil {
		t.Fatal(err)
	}
	if len(listBody.Items) != 1 {
		t.Fatalf("unexpected recording list: %s", listResponse.Body.String())
	}
	assertUsage("list", listBody.Items[0])

	detailResponse := httptest.NewRecorder()
	service.GetRecording(detailResponse, requestWithID(t, principal, recording))
	if detailResponse.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", detailResponse.Code, detailResponse.Body.String())
	}
	var detailBody usageSummary
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detailBody); err != nil {
		t.Fatal(err)
	}
	assertUsage("detail", detailBody)
}

func TestAttemptReturnsChunkBodyEvidenceAlongsideMetadata(t *testing.T) {
	db := queryTestDB(t)
	service := &Service{DB: db}
	principal := queryProject(t, db)
	ctx := context.Background()
	run := "run-query-body-" + uuid.NewString()[:8]
	recording := run + "#0000"
	nativeAttempt := "attempt-1"
	attempt := run + "~" + nativeAttempt
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = byte(index + 1)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, principal.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state) values($1,$2,$3,'sealed')`, recording, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,processor_version) values($1,$2,$3,$4,$5,'proxy','test')`, attempt, nativeAttempt, recording, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,payload_sha256,payload_size,raw_media_type,batch_id)
		values($1,1,1,now(),'proxy','response_body_chunk',$2,'{"chunk_sequence":1,"captured_size":12,"observed_size":12}',$3,12,'application/json','batch-1')`, recording, nativeAttempt, digest); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	service.GetAttempt(response, requestWithID(t, principal, attempt))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		ResponseBodyParts []struct {
			SHA256        string `json:"sha256"`
			Size          int64  `json:"size"`
			ChunkSequence int64  `json:"chunk_sequence"`
		} `json:"response_body_parts"`
		Events []struct {
			Payload       json.RawMessage `json:"payload"`
			PayloadSHA256 string          `json:"payload_sha256"`
		} `json:"events"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.ResponseBodyParts) != 1 || body.ResponseBodyParts[0].SHA256 == "" || body.ResponseBodyParts[0].Size != 12 || body.ResponseBodyParts[0].ChunkSequence != 1 {
		t.Fatalf("body part evidence missing: %#v", body.ResponseBodyParts)
	}
	if len(body.Events) != 1 || len(body.Events[0].Payload) == 0 || body.Events[0].PayloadSHA256 == "" {
		t.Fatalf("raw event metadata or blob reference missing: %#v", body.Events)
	}
}

func TestSessionDerivedQueriesRemainProjectScoped(t *testing.T) {
	db := queryTestDB(t)
	service := &Service{DB: db}
	owner := queryProject(t, db)
	other := queryProject(t, db)
	rootID := "session-" + uuid.NewString()
	otherChild := "session-" + uuid.NewString()
	ownerRun := "run-owner-" + uuid.NewString()
	otherRun := "run-other-" + uuid.NewString()
	if _, err := db.Pool.Exec(context.Background(), `insert into capture_runs(id,project_id) values($1,$2),($3,$4)`, ownerRun, owner.ProjectID, otherRun, other.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into sessions(id,project_id,capture_run_id,kind,role,turns,inference_count,relation_revision) values($1,$2,$3,'native','main','[]',0,1)`, rootID, owner.ProjectID, ownerRun); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into sessions(id,project_id,capture_run_id,kind,role,parent_session_id,turns,inference_count,relation_revision) values($1,$2,$3,'native','subagent',$4,'[]',0,1)`, otherChild, other.ProjectID, otherRun, rootID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into model_inferences(id,recording_id,capture_run_id,project_id,status,processor_version,session_id) values($1,'other-recording',$2,$3,'complete','test',$4)`, "inference-"+uuid.NewString(), otherRun, other.ProjectID, rootID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into relations(project_id,capture_run_id,type,from_id,to_id,status,evidence,revision) values($1,$2,'parent',$3,$4,'inferred','[]',1)`, other.ProjectID, otherRun, rootID, otherChild); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	service.GetSession(response, requestWithID(t, owner, rootID))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"children", "inferences", "relations"} {
		items, ok := body[field].([]any)
		if !ok || len(items) != 0 {
			t.Fatalf("cross-project %s leaked: %#v", field, body[field])
		}
	}
	collector := owner
	collector.Kind = auth.KindCollector
	collector.Role = ""
	denied := httptest.NewRecorder()
	service.GetSession(denied, requestWithID(t, collector, rootID))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("collector read console session status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestDeletingRunImmediatelyFencesSensitiveReadModels(t *testing.T) {
	db := queryTestDB(t)
	service := &Service{DB: db}
	principal := queryProject(t, db)
	ctx := context.Background()
	run := "run-query-deleting-" + uuid.NewString()[:8]
	recording := run + "#0000"
	attempt := run + "~attempt"
	inference := run + "~inference"
	session := run + "~session"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,state,command,metadata) values($1,$2,'deleting','secret-command','{"secret":"run"}')`, run, principal.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,manifest,coverage,integrity_alerts) values($1,$2,$3,'deleting','{"secret":"manifest"}','{"secret":"coverage"}','[{"secret":"alert"}]')`, recording, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,payload,batch_id) values($1,1,1,now(),'proxy','response_body','{"secret":"event"}','batch')`, recording); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,request_body,processor_version) values($1,'native',$2,$3,$4,'proxy','{"secret":"attempt"}','test')`, attempt, recording, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,recording_id,capture_run_id,project_id,status,request,processor_version,session_id) values($1,$2,$3,$4,'complete','{"secret":"inference"}','test',$5)`, inference, recording, run, principal.ProjectID, session); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into sessions(id,project_id,capture_run_id,kind,turns,inference_count,relation_revision) values($1,$2,$3,'native','[{"secret":"session"}]',1,1)`, session, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}

	recordingResponse := httptest.NewRecorder()
	service.GetRecording(recordingResponse, requestWithID(t, principal, recording))
	if recordingResponse.Code != http.StatusOK {
		t.Fatalf("deletion tombstone status=%d body=%s", recordingResponse.Code, recordingResponse.Body.String())
	}
	if bytes := recordingResponse.Body.Bytes(); strings.Contains(string(bytes), "secret") || strings.Contains(string(bytes), "command") || strings.Contains(string(bytes), "manifest") {
		t.Fatalf("deletion tombstone leaked sensitive fields: %s", bytes)
	}

	for name, id := range map[string]string{"attempt": attempt, "inference": inference, "session": session, "timeline": recording, "events": recording} {
		response := httptest.NewRecorder()
		request := requestWithID(t, principal, id)
		switch name {
		case "attempt":
			service.GetAttempt(response, request)
		case "inference":
			service.GetInference(response, request)
		case "session":
			service.GetSession(response, request)
		case "timeline":
			service.Timeline(response, request)
		case "events":
			service.Events(response, request)
		}
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s remained readable during deletion: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){"recordings": service.ListRecordings, "runs": service.ListRuns, "attempts": service.ListAttempts} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/v1/"+name, nil).WithContext(auth.WithPrincipal(ctx, principal)))
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("%s list exposed deleting data: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
}

func TestTimelineIncludesLifecycleEvidenceAcrossRecordingSegments(t *testing.T) {
	db := queryTestDB(t)
	service := &Service{DB: db}
	principal := queryProject(t, db)
	run := "run-query-segments-" + uuid.NewString()[:8]
	first, second := run+"#0000", run+"#0001"
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, principal.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,segment_no,sequence_base,durable_seq,parsed_seq,state,final_seq) values
		($1,$3,$4,0,0,1,1,'sealed',1), ($2,$3,$4,1,1,2,2,'sealed',2)`, first, second, principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,task_id,agent_session_id,payload,batch_id) values
		($1,1,1,now(),'runner','run_start','task-a','session-shared','{}','batch-1'),
		($2,2,2,now(),'runner','run_end','task-a','session-shared','{}','batch-2')`, first, second); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_tasks(id,project_id,capture_run_id,split_policy,boundary_kind,native_id,session_ids,event_count,first_seq,last_seq,first_seen_at,last_seen_at)
		values($1,$2,$3,'agent-task-or-session-v1','agent_task','task-a','["session-shared"]',2,1,2,now(),now())`, run+"~task-a", principal.ProjectID, run); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	service.Timeline(response, requestWithID(t, principal, second))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	lifecycle, ok := body["lifecycle"].([]any)
	if !ok || len(lifecycle) != 2 {
		t.Fatalf("cross-segment lifecycle missing: %#v", body["lifecycle"])
	}
	firstEvent, _ := lifecycle[0].(map[string]any)
	secondEvent, _ := lifecycle[1].(map[string]any)
	if firstEvent["recording_id"] != first || secondEvent["recording_id"] != second {
		t.Fatalf("cross-segment lifecycle identities are wrong: %#v", lifecycle)
	}
	if firstEvent["task_id"] != "task-a" || secondEvent["task_id"] != "task-a" {
		t.Fatalf("task identity did not survive lifecycle query: %#v", lifecycle)
	}
	tasks, ok := body["tasks"].([]any)
	if !ok || len(tasks) != 1 {
		t.Fatalf("capture tasks missing from timeline: %#v", body["tasks"])
	}
	task, _ := tasks[0].(map[string]any)
	if task["split_policy"] != "agent-task-or-session-v1" || task["native_id"] != "task-a" {
		t.Fatalf("capture task is malformed: %#v", task)
	}
}
