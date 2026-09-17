package exporter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func exportTestDB(t *testing.T) *store.DB {
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

func exportProject(t *testing.T, db *store.DB) (auth.Principal, string, string) {
	t.Helper()
	tenant, project := uuid.New(), uuid.New()
	run := "run-export-" + uuid.NewString()[:8]
	recording := run + "#0000"
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "export-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,$3)`, project, tenant, "export-"+project.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id,ended_at) values($1,$2,now())`, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,coverage) values($1,$2,$3,'sealed','{"claim":"client-complete"}')`, recording, project, run); err != nil {
		t.Fatal(err)
	}
	return auth.Principal{Kind: auth.KindUser, TenantID: tenant, ProjectID: project, Subject: "admin@example.test", Role: auth.RoleAdmin}, run, recording
}

func TestNormalizedJSONLExportIsBoundedVerifiedAndIdempotent(t *testing.T) {
	db := exportTestDB(t)
	p, run, recording := exportProject(t, db)
	ctx := context.Background()
	inference := run + "~inference-1"
	attempt := run + "~attempt-1"
	if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,native_id,recording_id,capture_run_id,project_id,status,attempt_count,first_attempt_at,model,api_mode,request,response,usage,normalized,server_state,task_id,session_id,turn_id,evidence_refs,processor_version)
		values($1,'inference-1',$2,$3,$4,'complete',1,now(),'model-a','responses','{"input":"hello"}','{"output":"world"}','{"input_tokens":1,"output_tokens":1}','{"api_mode":"responses","messages":[],"message_hashes":[],"fingerprint":"f","input_hash":"i","response_text":"world"}','none','task-a','session-a','turn-a','[]','test')`, inference, recording, run, p.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,inference_id,source,terminal_state,status_code,processor_version) values($1,'attempt-1',$2,$3,$4,$5,'proxy','completed',200,'test')`, attempt, recording, p.ProjectID, run, inference); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into relations(project_id,capture_run_id,type,from_id,to_id,status,confidence,evidence,revision) values($1,$2,'belongs_to_turn',$3,'turn-a','exact',1.0,'[]',1)`, p.ProjectID, run, inference); err != nil {
		t.Fatal(err)
	}
	exportID := uuid.New()
	filename := run + ".normalized.jsonl"
	if _, err := db.Pool.Exec(ctx, `insert into exports(id,project_id,capture_run_id,format,filename,media_type,expires_at,created_by) values($1,$2,$3,$4,$5,$6,now()+interval '7 days',$7)`, exportID, p.ProjectID, run, formatNormalizedJSONL, filename, mediaTypeJSONL, p.Subject); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(exportInput{ExportID: exportID.String(), Format: formatNormalizedJSONL})
	job := &jobs.Job{ProjectID: p.ProjectID, Type: jobs.TypeExport, CaptureRunID: &run, InputRef: input, ProcessorVersion: Version, Attempts: 1}
	obj, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{DB: db, Obj: obj}
	if err := service.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := service.Run(ctx, job); err != nil {
		t.Fatalf("idempotent rerun failed: %v", err)
	}
	var state, key string
	var digest []byte
	var size int64
	if err := db.Pool.QueryRow(ctx, `select state,object_key,sha256,byte_length from exports where id=$1`, exportID).Scan(&state, &key, &digest, &size); err != nil {
		t.Fatal(err)
	}
	if state != "ready" || len(digest) != sha256.Size || size <= 0 {
		t.Fatalf("bad export metadata state=%s digest=%x size=%d", state, digest, size)
	}
	rc, err := obj.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	actual := sha256.Sum256(data)
	if !bytes.Equal(actual[:], digest) || int64(len(data)) != size {
		t.Fatalf("stored export mismatch: hash=%s want=%s bytes=%d want=%d", hex.EncodeToString(actual[:]), hex.EncodeToString(digest), len(data), size)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("expected one JSONL row, got %d", len(lines))
	}
	var row map[string]any
	if err := json.Unmarshal(lines[0], &row); err != nil {
		t.Fatal(err)
	}
	if row["schema_version"] != "iorec-platform-normalized-jsonl-v1" || row["capture_run_id"] != run || row["inference_id"] != inference {
		t.Fatalf("unexpected export row: %#v", row)
	}
	if got, ok := row["attempts"].([]any); !ok || len(got) != 1 {
		t.Fatalf("attempt evidence missing: %#v", row["attempts"])
	}
	if got, ok := row["coverage"].([]any); !ok || len(got) != 1 {
		t.Fatalf("coverage evidence missing: %#v", row["coverage"])
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set state='deleting' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	downloadRequest := httptest.NewRequest(http.MethodGet, "/v1/exports/"+exportID.String()+"/download", nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", exportID.String())
	downloadRequest = downloadRequest.WithContext(auth.WithPrincipal(context.WithValue(downloadRequest.Context(), chi.RouteCtxKey, route), p))
	downloadResponse := httptest.NewRecorder()
	service.Download(downloadResponse, downloadRequest)
	if downloadResponse.Code != http.StatusNotFound || bytes.Contains(downloadResponse.Body.Bytes(), data) {
		t.Fatalf("export remained readable after deletion started: status=%d body=%s", downloadResponse.Code, downloadResponse.Body.String())
	}
	if _, err := db.Pool.Exec(ctx, `update capture_runs set state='active' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(obj.Root, filepath.FromSlash(key)), bytes.Repeat([]byte{'x'}, len(data)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.Run(ctx, job); err == nil {
		t.Fatal("same-length export object corruption passed the idempotent verification path")
	}
	if err := os.WriteFile(filepath.Join(obj.Root, filepath.FromSlash(key)), data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Pool.Exec(ctx, `update exports set expires_at=now()-interval '1 second' where id=$1`, exportID); err != nil {
		t.Fatal(err)
	}
	if err := service.SweepExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select state from exports where id=$1`, exportID).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("export was not expired: state=%s err=%v", state, err)
	}
	if _, err := obj.Stat(ctx, key); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("expired object remains available: %v", err)
	}
	var audits int
	if err := db.Pool.QueryRow(ctx, `select count(*) from audit_log where project_id=$1 and entity_id=$2 and action='export.expire'`, p.ProjectID, exportID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("expiry audit missing: count=%d err=%v", audits, err)
	}
}

func TestCreateExportRequiresAdminAndFinalizedRun(t *testing.T) {
	db := exportTestDB(t)
	p, run, _ := exportProject(t, db)
	obj, _ := objstore.NewFS(t.TempDir())
	service := &Service{DB: db, Obj: obj}
	body := []byte(`{"capture_run_id":"` + run + `","format":"normalized-jsonl"}`)

	viewer := p
	viewer.Role = auth.RoleViewer
	viewerRequest := httptest.NewRequest(http.MethodPost, "/v1/exports", bytes.NewReader(body)).WithContext(auth.WithPrincipal(context.Background(), viewer))
	viewerResponse := httptest.NewRecorder()
	service.Create(viewerResponse, viewerRequest)
	if viewerResponse.Code != http.StatusForbidden {
		t.Fatalf("viewer export status=%d body=%s", viewerResponse.Code, viewerResponse.Body.String())
	}

	adminRequest := httptest.NewRequest(http.MethodPost, "/v1/exports", bytes.NewReader(body)).WithContext(auth.WithPrincipal(context.Background(), p))
	adminResponse := httptest.NewRecorder()
	service.Create(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusAccepted {
		t.Fatalf("admin export status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	var response struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &response); err != nil || response.ID == uuid.Nil {
		t.Fatalf("bad create response: %s err=%v", adminResponse.Body.String(), err)
	}
	var exportCount, jobCount, auditCount int
	if err := db.Pool.QueryRow(context.Background(), `select count(*) from exports where id=$1 and project_id=$2`, response.ID, p.ProjectID).Scan(&exportCount); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(context.Background(), `select count(*) from processing_jobs where project_id=$1 and capture_run_id=$2 and type='export'`, p.ProjectID, run).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(context.Background(), `select count(*) from audit_log where project_id=$1 and entity_id=$2 and action='export.create'`, p.ProjectID, response.ID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if exportCount != 1 || jobCount != 1 || auditCount != 1 {
		t.Fatalf("create was not atomic: export=%d job=%d audit=%d", exportCount, jobCount, auditCount)
	}

	openRun := "run-export-open-" + uuid.NewString()[:8]
	if _, err := db.Pool.Exec(context.Background(), `insert into capture_runs(id,project_id) values($1,$2)`, openRun, p.ProjectID); err != nil {
		t.Fatal(err)
	}
	openBody := []byte(`{"capture_run_id":"` + openRun + `","format":"normalized-jsonl"}`)
	openRequest := httptest.NewRequest(http.MethodPost, "/v1/exports", bytes.NewReader(openBody)).WithContext(auth.WithPrincipal(context.Background(), p))
	openResponse := httptest.NewRecorder()
	service.Create(openResponse, openRequest)
	if openResponse.Code != http.StatusConflict {
		t.Fatalf("open capture run export status=%d body=%s", openResponse.Code, openResponse.Body.String())
	}
}
