package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/pipeline"
)

func progressFixture(id string, seq int64, tools []pipeline.NToolCall, messages []pipeline.NMessage) progressInput {
	return progressInput{ID: id, RecordingID: "run#0000", FirstSeq: seq, LastSeq: seq + 1,
		Normalized: pipeline.Normalized{ResponseToolCalls: tools, Messages: messages}}
}

func TestProgressRepeatedContextIsNotRepeatedExecution(t *testing.T) {
	input := []progressInput{
		progressFixture("a", 1, []pipeline.NToolCall{{ID: "t", Name: "exec", Arguments: "echo yes"}}, nil),
		progressFixture("b", 3, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "t", Text: "yes"}}),
		progressFixture("c", 5, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "t", Text: "yes"}}),
	}
	input[0].Normalized.ResponseID = "r1"
	input[1].Normalized.PreviousResponseID = "r1"
	input[1].RecordingID = "run#0001"
	calls, summary := buildProgress(input)
	if summary.Requested != 1 || summary.ResultsObserved != 1 || summary.UnmatchedResults != 0 {
		t.Fatalf("inflated tool counts: %+v", summary)
	}
	tool := calls[0].Tools[0]
	if tool.State != "result_observed" || tool.ObservationCount != 2 || tool.ResultVariants != 1 || tool.Result.Evidence.RecordingID != "run#0001" || tool.ArgumentsPreview != "echo yes" {
		t.Fatalf("lost evidence or duplicate result: %+v", tool)
	}
	if len(calls[1].Predecessors) != 2 || len(calls[2].Predecessors) != 0 || tool.Result.CallOrdinal != 2 {
		t.Fatal("explicit predecessor missing or historical context presented as a new step")
	}
}

func TestProgressAmbiguityConflictAndMissingEvidence(t *testing.T) {
	input := []progressInput{
		progressFixture("a", 1, []pipeline.NToolCall{{ID: "duplicate", Name: "exec"}, {ID: "unique", Name: "read"}, {Name: "unknown"}, {ID: "no-result", Name: "write"}}, nil),
		progressFixture("b", 3, []pipeline.NToolCall{{ID: "duplicate", Name: "exec"}}, nil),
		progressFixture("c", 5, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "duplicate", Text: "x"}, {Role: "tool", ToolCallID: "unique", Text: "first"}, {Role: "tool", ToolCallID: "orphan", Text: "y"}}),
		progressFixture("d", 7, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "unique", Text: "conflict"}}),
	}
	calls, summary := buildProgress(input)
	if summary.Requested != 5 || summary.Ambiguous != 3 || summary.Conflicting != 1 || summary.AwaitingEvidence != 1 || summary.ResultsObserved != 0 || summary.UnmatchedResults != 2 {
		t.Fatalf("unsafe success or ambiguity handling: %+v", summary)
	}
	if calls[0].Tools[1].ResultVariants != 2 || calls[0].Tools[0].Result != nil || len(calls[2].Predecessors) != 1 {
		t.Fatal("ambiguous result was attributed")
	}
}

func TestProgressDoesNotInferAcrossSessionsOrWithoutSequence(t *testing.T) {
	for _, missingSeq := range []bool{false, true} {
		input := []progressInput{
			progressFixture("a", 1, []pipeline.NToolCall{{ID: "t", Name: "exec"}}, nil),
			progressFixture("b", 3, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "t", Text: "done"}}),
		}
		if missingSeq {
			input[0].FirstSeq = 0
		} else {
			input[0].SessionID, input[1].SessionID = "one", "two"
			input[0].NativeSession, input[1].NativeSession = true, true
		}
		calls, summary := buildProgress(input)
		if summary.ResultsObserved != 0 || summary.UnmatchedResults != 1 || len(calls[1].Predecessors) != 0 {
			t.Fatal("invented a cross-session/unknown-order edge")
		}
	}
}

func TestProgressInferredSessionSplitsDoNotOverrideExplicitToolID(t *testing.T) {
	input := []progressInput{
		progressFixture("a", 1, []pipeline.NToolCall{{ID: "t", Name: "exec"}}, nil),
		progressFixture("b", 3, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "t", Text: "done"}}),
	}
	input[0].SessionID, input[1].SessionID = "inferred-one", "inferred-two"
	calls, summary := buildProgress(input)
	if summary.ResultsObserved != 1 || len(calls[1].Predecessors) != 1 {
		t.Fatal("a heuristic session split hid an explicit unique tool result")
	}
}

func TestProgressPreviewPreservesUTF8AndBounds(t *testing.T) {
	s := ""
	for range 1300 {
		s += "录"
	}
	got := preview(s)
	if len([]rune(got)) != progressPreviewRunes+1 || len(got) != (progressPreviewRunes+1)*3 {
		t.Fatal("preview split UTF-8 or failed bound")
	}
}

func TestProgressWorkBudgetAndDistinctArguments(t *testing.T) {
	input := []progressInput{progressFixture("a", 1, []pipeline.NToolCall{
		{ID: "same", Name: "exec", Arguments: "one"}, {ID: "same", Name: "exec", Arguments: "two"},
	}, nil), progressFixture("b", 3, nil, []pipeline.NMessage{{Role: "tool", ToolCallID: "same", Text: "ok"}})}
	_, summary := buildProgress(input)
	if summary.Requested != 2 || summary.Ambiguous != 2 || summary.ResultsObserved != 0 {
		t.Fatal("different operations with the same ID were collapsed")
	}
	if !progressWithinWorkBudget(input) {
		t.Fatal("ordinary graph rejected")
	}
	input[0].Normalized.ResponseToolCalls = make([]pipeline.NToolCall, 10001)
	if progressWithinWorkBudget(input) {
		t.Fatal("tool ceiling bypassed")
	}
	input[0].Normalized.ResponseToolCalls = nil
	input[0].Normalized.Messages = make([]pipeline.NMessage, 100001)
	if progressWithinWorkBudget(input) {
		t.Fatal("message ceiling bypassed")
	}
	input[0].Normalized.Messages = nil
	input[0].Normalized.ResponseToolCalls = make([]pipeline.NToolCall, 1100)
	input[1].Normalized.Messages = make([]pipeline.NMessage, 1000)
	for i := range input[0].Normalized.ResponseToolCalls {
		input[0].Normalized.ResponseToolCalls[i].ID = "duplicate"
	}
	for i := range input[1].Normalized.Messages {
		input[1].Normalized.Messages[i] = pipeline.NMessage{Role: "tool", ToolCallID: "duplicate"}
	}
	if progressWithinWorkBudget(input) {
		t.Fatal("quadratic matching budget bypassed")
	}
}

func TestProgressQuerySeparatesCountsAcrossSegmentsAndFences(t *testing.T) {
	db := queryTestDB(t)
	s := &Service{DB: db}
	p, other := queryProject(t, db), queryProject(t, db)
	ctx := context.Background()
	run := "progress-" + uuid.NewString()
	rec0, rec1 := run+"#0000", run+"#0001"
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, p.ProjectID); err != nil {
		t.Fatal(err)
	}
	for i, rec := range []string{rec0, rec1} {
		if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,segment_no,sequence_base) values($1,$2,$3,'sealed',$4,$5)`, rec, p.ProjectID, run, i, i*10); err != nil {
			t.Fatal(err)
		}
	}
	fixtures := []struct {
		id, rec, source, kind, api, norm string
		seq                              int
	}{
		{"ws", rec0, "proxy", "websocket_connection", "responses", "null", 1},
		{"call1", rec0, "proxy:websocket-call", "websocket_call", "responses", `{"response_id":"r1","response_tool_calls":[{"id":"tool","name":"exec","arguments":"echo ok"}]}`, 2},
		{"hook1", rec0, "hook:hermes", "request", "responses", `{"response_tool_calls":[{"id":"tool","name":"exec"}]}`, 3},
		{"probe", rec0, "proxy", "request", "unknown", "null", 4},
		{"call2", rec1, "proxy", "request", "chat_completions", `{"messages":[{"role":"tool","tool_call_id":"tool","text":"ok"}],"previous_response_id":"r1"}`, 11},
		{"hook2", rec1, "hook:hermes", "request", "chat_completions", "null", 12},
	}
	for _, f := range fixtures {
		if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,entity_kind,api_mode,normalized,first_seq,last_seq,processor_version)
 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,'test')`, run+"~"+f.id, f.id, f.rec, p.ProjectID, run, f.source, f.kind, f.api, f.norm, f.seq); err != nil {
			t.Fatal(err)
		}
	}
	for i, event := range []string{"websocket_frame", "sse_event", "tool_call", "run_start"} {
		if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,payload,batch_id) values($1,$2,$2,now(),'proxy',$3,'{}','b')`, rec0, i+1, event); err != nil {
			t.Fatal(err)
		}
	}
	get := func(principal auth.Principal, query string) (*httptest.ResponseRecorder, map[string]any) {
		r := requestWithID(t, principal, rec1)
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		s.GetProgress(w, r)
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return w, body
	}
	w, body := get(p, "limit=1")
	if w.Code != http.StatusOK {
		t.Fatalf("progress status %d: %s", w.Code, w.Body.String())
	}
	summary := body["summary"].(map[string]any)
	for key, want := range map[string]float64{"model_calls": 2, "websocket_connections": 1, "hook_observations": 2, "other_http_requests": 1, "all_attempt_rows": 6, "raw_events": 4, "stream_events": 2} {
		if summary[key] != want {
			t.Fatalf("%s=%v want %v", key, summary[key], want)
		}
	}
	if summary["tools"].(map[string]any)["results_observed"] != float64(1) || body["next_offset"] != float64(1) || len(body["items"].([]any)) != 1 {
		t.Fatal("tool/segment/pagination count mismatch")
	}
	snapshot := body["snapshot"].(string)
	w, page := get(p, "limit=1&offset=1&snapshot="+snapshot)
	if w.Code != http.StatusOK || page["next_offset"] != nil || page["items"].([]any)[0].(map[string]any)["ordinal"] != float64(2) {
		t.Fatal("second page missing or repeated")
	}
	for _, bad := range []string{"offset=-1", "offset=no", "offset=9999999999999999999999"} {
		if w, _ := get(p, bad); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid cursor accepted: %s", bad)
		}
	}
	if w, _ := get(other, ""); w.Code != http.StatusNotFound {
		t.Fatal("cross-project read allowed")
	}
	collector := p
	collector.Kind = auth.KindCollector
	if w, _ := get(collector, ""); w.Code != http.StatusForbidden {
		t.Fatal("collector can read model bodies")
	}
	if _, err := db.Pool.Exec(ctx, `update model_attempts set normalized=normalized||'{"response_text":"changed"}'::jsonb where id=$1`, run+"~call2"); err != nil {
		t.Fatal(err)
	}
	if w, _ := get(p, "snapshot="+snapshot); w.Code != http.StatusConflict {
		t.Fatal("mixed a reprocessed projection with an old page")
	}
	setNorm := func(value any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `update model_attempts set normalized=$1 where id=$2`, value, run+"~call2"); err != nil {
			t.Fatal(err)
		}
	}
	setNorm(nil)
	if w, body := get(p, ""); w.Code != 200 || body["summary"].(map[string]any)["normalization_pending"] != float64(1) {
		t.Fatal("missing normalization hidden")
	}
	setNorm(`{"messages":"malformed"}`)
	if w, _ := get(p, ""); w.Code != 409 {
		t.Fatal("malformed normalized body accepted")
	}
	large, _ := json.Marshal(map[string]string{"response_text": strings.Repeat("x", 8<<20)})
	setNorm(string(large))
	if w, _ := get(p, ""); w.Code != 413 {
		t.Fatal("oversized normalized body accepted")
	}
	setNorm(`{}`)
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,entity_kind,api_mode,normalized,first_seq,last_seq,processor_version)
 select $1||'~extra-'||n,'extra-'||n,$2,$3,$1,'proxy','request','responses','{}'::jsonb,100+n,100+n,'test' from generate_series(1,40) n`, run, rec1, p.ProjectID); err != nil {
		t.Fatal(err)
	}
	w, first := get(p, "")
	if w.Code != 200 || len(first["items"].([]any)) != 25 || first["total"] != float64(42) {
		t.Fatal("default long-run page incorrect")
	}
	w, second := get(p, "offset=25&snapshot="+first["snapshot"].(string))
	if w.Code != 200 || len(second["items"].([]any)) != 17 || second["next_offset"] != nil || second["items"].([]any)[0].(map[string]any)["ordinal"] != float64(26) {
		t.Fatal("long-run page loses or repeats steps")
	}
	if _, err := db.Pool.Exec(ctx, `update model_attempts set ended_at=now() where id=$1`, run+"~call2"); err != nil {
		t.Fatal(err)
	}
	if w, _ := get(p, "snapshot="+first["snapshot"].(string)); w.Code != 409 {
		t.Fatal("timestamp changed without invalidating page")
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set state='deleted' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if w, _ := get(p, ""); w.Code != 404 {
		t.Fatal("deleted run exposes progress")
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set state='active' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"expired", "expiring", "deleting", "deleted"} {
		if _, err := db.Pool.Exec(ctx, `update recordings set state=$1 where id=$2`, state, rec1); err != nil {
			t.Fatal(err)
		}
		if w, _ := get(p, ""); w.Code != http.StatusNotFound {
			t.Fatal(fmt.Sprintf("%s recording fence bypassed", state))
		}
	}
}
