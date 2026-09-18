package query

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestWebSocketChildQueryReturnsOnlyAssignedEvidence(t *testing.T) {
	db := queryTestDB(t)
	s := &Service{DB: db}
	p := queryProject(t, db)
	other := queryProject(t, db)
	ctx := context.Background()
	run := "query-ws-" + uuid.NewString()
	rec := run + "#0000"
	parent := run + "~connection"
	child := run + "~call"
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`insert into capture_runs(id,project_id) values($1,$2)`, []any{run, p.ProjectID}},
		{`insert into recordings(id,project_id,capture_run_id,state) values($1,$2,$3,'sealed')`, []any{rec, p.ProjectID, run}},
		{`insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,processor_version,entity_kind) values($1,'connection',$2,$3,$4,'proxy','test','websocket_connection')`, []any{parent, rec, p.ProjectID, run}},
		{`insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,source,processor_version,entity_kind,parent_attempt_id) values($1,'call',$2,$3,$4,'proxy:websocket-call','test','websocket_call',$5)`, []any{child, rec, p.ProjectID, run, parent}},
		{`insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,batch_id) values($1,1,1,now(),'proxy','websocket_frame','connection','{"direction":"client_to_upstream","opcode":"text"}','b'),($1,2,2,now(),'proxy','websocket_frame','connection','{"direction":"upstream_to_client","opcode":"text"}','b'),($1,3,3,now(),'proxy','websocket_frame','connection','{"direction":"upstream_to_client","opcode":"text"}','b')`, []any{rec}},
		{`insert into attempt_event_links(project_id,parent_attempt_id,recording_id,seq,call_attempt_id,reason,processor_version) values($1,$2,$3,1,$4,'request','test'),($1,$2,$3,2,null,'unresolved_response','test'),($1,$2,$3,3,$4,'explicit_response_id','test')`, []any{p.ProjectID, parent, rec, child}},
	} {
		if _, err := db.Pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	s.GetAttempt(response, requestWithID(t, p, child))
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Events           []struct{ Seq int64 }
		ParentConnection map[string]any `json:"parent_connection"`
		RequestParts     []any          `json:"request_body_parts"`
		ResponseParts    []any          `json:"response_body_parts"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 2 || body.Events[0].Seq != 1 || body.Events[1].Seq != 3 || body.ParentConnection["id"] != parent || len(body.RequestParts) != 1 || len(body.ResponseParts) != 1 {
		t.Fatalf("mixed call evidence: %+v", body)
	}
	response = httptest.NewRecorder()
	s.GetAttempt(response, requestWithID(t, p, parent))
	var parentBody struct {
		Events []any
		Calls  []any
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parentBody); err != nil {
		t.Fatal(err)
	}
	if len(parentBody.Events) != 3 || len(parentBody.Calls) != 1 {
		t.Fatal("parent lost unresolved evidence or call navigation")
	}
	response = httptest.NewRecorder()
	s.GetAttempt(response, requestWithID(t, other, child))
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-project child access: %d", response.Code)
	}
}
