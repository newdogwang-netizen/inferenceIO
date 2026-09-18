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
	getPage := func(id, query string) (attemptEventPage, int) {
		request := requestWithID(t, p, id)
		request.URL.RawQuery = query
		rr := httptest.NewRecorder()
		s.GetAttemptEvents(rr, request)
		var page attemptEventPage
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
		}
		return page, rr.Code
	}
	page, status := getPage(child, "limit=1")
	if status != http.StatusOK || page.Total != 2 || !page.HasMore || page.NextAfterSeq == nil || *page.NextAfterSeq != 1 || len(page.Items) != 1 {
		t.Fatalf("first child page: %+v status %d", page, status)
	}
	page, status = getPage(child, "limit=1&after_seq=1")
	if status != http.StatusOK || page.HasMore || page.NextAfterSeq != nil || len(page.Items) != 1 || page.Items[0]["seq"] != float64(3) {
		t.Fatalf("second child page: %+v status %d", page, status)
	}
	page, status = getPage(parent, "filter=unresolved")
	if status != http.StatusOK || page.Total != 1 || len(page.Items) != 1 || page.Items[0]["seq"] != float64(2) {
		t.Fatalf("unresolved page: %+v status %d", page, status)
	}
	for _, query := range []string{"after_seq=-1", "after_seq=not-an-integer", "after_seq=999999999999999999999", "filter=sql"} {
		if _, status := getPage(child, query); status != http.StatusBadRequest {
			t.Fatalf("invalid query accepted: %s -> %d", query, status)
		}
	}
	if _, err := db.Pool.Exec(ctx, `insert into recording_events(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,batch_id) select $1,n,n,now(),'proxy','websocket_frame','connection','{"direction":"upstream_to_client","opcode":"text"}','b' from generate_series(4,1204) as n`, rec); err != nil {
		t.Fatal(err)
	}
	page, status = getPage(parent, "")
	if status != http.StatusOK || len(page.Items) != 200 || page.Total != 1204 || !page.HasMore {
		t.Fatalf("default page not bounded: %d items of %d", len(page.Items), page.Total)
	}
	page, status = getPage(parent, "limit=99999")
	if status != http.StatusOK || len(page.Items) != 1000 || page.Limit != 1000 {
		t.Fatal("page limit not capped")
	}
	response = httptest.NewRecorder()
	s.GetAttempt(response, requestWithID(t, p, parent))
	if err := json.Unmarshal(response.Body.Bytes(), &parentBody); err != nil {
		t.Fatal(err)
	}
	if len(parentBody.Events) != 200 {
		t.Fatal("legacy attempt detail unbounded")
	}
	response = httptest.NewRecorder()
	s.GetAttemptEvents(response, requestWithID(t, other, parent))
	if response.Code != http.StatusNotFound {
		t.Fatal("event page leaked across projects")
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set state='deleting' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if _, status := getPage(parent, ""); status != http.StatusNotFound {
		t.Fatal("deletion fence bypassed")
	}
}
