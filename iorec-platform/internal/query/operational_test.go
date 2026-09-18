package query

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/heidihealth/iorec-platform/internal/auth"
)

func TestBenchmarkResultImmutableScopedAuditedAndFenced(t *testing.T) {
	db := queryTestDB(t)
	s := &Service{DB: db}
	p, other := queryProject(t, db), queryProject(t, db)
	p.Role, other.Role = auth.RoleOperator, auth.RoleOperator
	run := "benchmark-" + uuid.NewString()
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, p.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state) values($1,$2,$3,'sealed')`, run+"#0000", p.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	body := `{"framework":"harbor","task":"html-js-filter","trial":"trial__abc","model":"openai/test","agent":"codex","status":"completed","reward":0,"artifact_sha256":"` + strings.Repeat("a", 64) + `"}`
	put := func(who auth.Principal, value string) *httptest.ResponseRecorder {
		r := requestWithID(t, who, run)
		r.Method = http.MethodPut
		r.Body = io.NopCloser(strings.NewReader(value))
		w := httptest.NewRecorder()
		s.PutBenchmarkResult(w, r)
		return w
	}
	viewer := p
	viewer.Role = auth.RoleViewer
	collector := p
	collector.Kind = auth.KindCollector
	for _, who := range []auth.Principal{viewer, collector} {
		if w := put(who, body); w.Code != 403 {
			t.Fatalf("write authorization %d", w.Code)
		}
	}
	if w := put(other, body); w.Code != 404 {
		t.Fatalf("cross project %d", w.Code)
	}
	for _, bad := range []string{strings.Replace(body, `"reward":0`, `"reward":1e999`, 1), strings.Replace(body, `"completed"`, `"timeout"`, 1), strings.Replace(body, `"task":"html-js-filter"`, `"task":"bad\nlog"`, 1), strings.Replace(body, strings.Repeat("a", 64), "invalid", 1)} {
		if w := put(p, bad); w.Code != 400 {
			t.Fatalf("accepted invalid result: %d", w.Code)
		}
	}
	first := put(p, body)
	if first.Code != 201 {
		t.Fatalf("first %d %s", first.Code, first.Body.String())
	}
	if w := put(p, body); w.Code != 200 {
		t.Fatalf("retry %d %s", w.Code, w.Body.String())
	}
	if w := put(p, strings.Replace(body, `"reward":0`, `"reward":1`, 1)); w.Code != 409 {
		t.Fatalf("conflict %d", w.Code)
	}
	var count int
	if err := db.Pool.QueryRow(ctx, `select count(*) from audit_log where project_id=$1 and action='benchmark.attach' and entity_id=$2`, p.ProjectID, run).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit count %d %v", count, err)
	}
	w := httptest.NewRecorder()
	s.GetRecording(w, requestWithID(t, p, run+"#0000"))
	var rec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["benchmark_result"].(map[string]any)["provenance"] != "operator_reported_not_recomputed" {
		t.Fatal("missing provenance")
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set state='deleting' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if w := put(p, body); w.Code != 404 {
		t.Fatal("deletion write fence")
	}
	w = httptest.NewRecorder()
	s.GetRecording(w, requestWithID(t, p, run+"#0000"))
	if strings.Contains(w.Body.String(), "benchmark_result") {
		t.Fatal("deleted benchmark visible")
	}
}

func TestSystemHealthRequiresLivePoolCoverage(t *testing.T) {
	db := queryTestDB(t)
	s := &Service{DB: db}
	p := queryProject(t, db)
	p.Role = auth.RoleOperator
	ctx := context.Background()
	owner := "health-" + uuid.NewString()
	// Dedicated test database, no real workers. Rows inserted here are isolated
	// by owner and removed after the test, including on assertion failures.
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `delete from worker_heartbeats where owner=$1`, owner) })
	check := func(want int) {
		w := httptest.NewRecorder()
		s.SystemHealth(w, requestWithID(t, p, "unused"))
		if w.Code != want {
			t.Fatalf("health want %d got %d: %s", want, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), owner) {
			t.Fatal("exposed host identity")
		}
	}
	check(503)
	pools := map[string]int{"decode": 1, "assemble": 1, "normalize": 1, "resolve": 1, "transport_audit": 1, "coverage": 1, "rules": 1, "export": 1}
	if _, err := db.Pool.Exec(ctx, `insert into worker_heartbeats(owner,pools) values($1,$2)`, owner, pools); err != nil {
		t.Fatal(err)
	}
	check(200)
	if _, err := db.Pool.Exec(ctx, `update worker_heartbeats set last_seen_at=now()-interval '46 seconds' where owner=$1`, owner); err != nil {
		t.Fatal(err)
	}
	check(503)
	pools["normalize"] = 0
	if _, err := db.Pool.Exec(ctx, `update worker_heartbeats set last_seen_at=now(),pools=$2 where owner=$1`, owner, pools); err != nil {
		t.Fatal(err)
	}
	check(503)
	p.Role = auth.RoleViewer
	check(403)
}
