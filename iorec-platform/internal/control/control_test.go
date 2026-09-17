package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func controlTestDB(t *testing.T) *store.DB {
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

func controlPrincipal(t *testing.T, db *store.DB) auth.Principal {
	tenant, project := uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(context.Background(), `insert into tenants(id,name) values($1,$2)`, tenant, "control-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into projects(id,tenant_id,name) values($1,$2,'control')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	return auth.Principal{Kind: auth.KindCollector, TenantID: tenant, ProjectID: project, Subject: "test"}
}

func controlAPIError(err error) (int, string) {
	var api *httpapi.APIError
	if errors.As(err, &api) {
		return api.Status, api.Code
	}
	return 0, ""
}

func validCapabilities() json.RawMessage {
	return json.RawMessage(`{"schema":"iorec.capabilities.v1","transport":{"http_body":"visible","sse":"visible","websocket":"visible","http2_decode":"absent","http3":"detect_only"},"sources":{"proxy":true}}`)
}

func TestRegistrationBindsCollectorSessionAndValidatesHealth(t *testing.T) {
	db := controlTestDB(t)
	service := &Service{DB: db}
	project := controlPrincipal(t, db)
	request := RegisterRequest{
		Name:         "iorec",
		Version:      "iorec/0.1.0",
		Hostname:     "redacted",
		OS:           "linux/x86_64",
		Capabilities: validCapabilities(),
	}
	registered, err := service.Register(context.Background(), project, request)
	if err != nil {
		t.Fatal(err)
	}
	if registered.CollectorID == uuid.Nil || registered.SessionToken == "" {
		t.Fatalf("invalid registration: %+v", registered)
	}
	collector := project
	collector.Kind = auth.KindCollector
	collector.CollectorID = registered.CollectorID

	other := uuid.New()
	request.CollectorID = &other
	if _, err := service.Register(context.Background(), collector, request); err == nil {
		t.Fatal("collector session re-registered a different collector")
	} else if status, code := controlAPIError(err); status != 403 || code != "forbidden" {
		t.Fatalf("unexpected re-registration error: %v", err)
	}

	if _, err := service.Heartbeat(context.Background(), collector, registered.CollectorID, HeartbeatRequest{Status: "healthy", SpoolBytesUsed: -1}); err == nil {
		t.Fatal("negative spool usage was accepted")
	} else if status, code := controlAPIError(err); status != 400 || code != "malformed_request" {
		t.Fatalf("unexpected heartbeat validation error: %v", err)
	}
	if _, err := service.Heartbeat(context.Background(), collector, registered.CollectorID, HeartbeatRequest{Status: "healthy"}); err != nil {
		t.Fatalf("valid heartbeat: %v", err)
	}

	request.CollectorID = nil
	request.Capabilities = nil
	if _, err := service.Register(context.Background(), project, request); err == nil {
		t.Fatal("registration without capabilities was accepted")
	} else if status, code := controlAPIError(err); status != 400 || code != "malformed_request" {
		t.Fatalf("unexpected missing-capabilities error: %v", err)
	}
}

func TestCollectorRequestValidationAndStateMachine(t *testing.T) {
	db := controlTestDB(t)
	service := &Service{DB: db}
	project := controlPrincipal(t, db)
	registered, err := service.Register(context.Background(), project, RegisterRequest{
		Name:         "iorec",
		Version:      "iorec/0.1.0",
		Hostname:     "redacted",
		OS:           "linux/x86_64",
		Capabilities: validCapabilities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	collector := project
	collector.CollectorID = registered.CollectorID
	user := project
	user.Kind = auth.KindUser
	user.Role = auth.RoleOperator
	user.Subject = "operator@example.test"

	invalid := []CreateRequest{
		{CollectorID: registered.CollectorID, Type: "backfill", Payload: json.RawMessage(`{"recording_id":"r","first_seq":9,"last_seq":2}`)},
		{CollectorID: registered.CollectorID, Type: "apply_config", Payload: json.RawMessage(`{}`)},
		{CollectorID: registered.CollectorID, Type: "upload_sensitive", Payload: json.RawMessage(`{"recording_id":"r","approval_id":"ok","kinds":["pcap","pcap"]}`)},
		{CollectorID: registered.CollectorID, Type: "pause", Payload: json.RawMessage(`[]`)},
		{CollectorID: registered.CollectorID, Type: "pause", ExpiresIn: 1},
	}
	for _, request := range invalid {
		if _, err := service.CreateCollectorRequest(context.Background(), user, request); err == nil {
			t.Fatalf("invalid request was accepted: %+v", request)
		}
	}

	id, err := service.CreateCollectorRequest(context.Background(), user, CreateRequest{
		CollectorID: registered.CollectorID,
		Type:        "pause",
		Payload:     json.RawMessage(`{"reason":"maintenance"}`),
		ExpiresIn:   60,
	})
	if err != nil {
		t.Fatal(err)
	}
	items, err := service.Poll(context.Background(), collector, 0)
	if err != nil || len(items) != 1 || items[0].ID != id {
		t.Fatalf("poll: items=%+v err=%v", items, err)
	}
	if early, err := service.Poll(context.Background(), collector, 0); err != nil || len(early) != 0 {
		t.Fatalf("delivered request escaped its lease: items=%+v err=%v", early, err)
	}
	if _, err := db.Pool.Exec(context.Background(), `update collector_requests set delivered_at=now()-$2::interval where id=$1`, id, 2*DeliveryLease); err != nil {
		t.Fatal(err)
	}
	if retried, err := service.Poll(context.Background(), collector, 0); err != nil || len(retried) != 1 || retried[0].ID != id {
		t.Fatalf("expired delivery lease was not retried: items=%+v err=%v", retried, err)
	}
	acked := ResultRequest{Status: "acked", Result: json.RawMessage(`{"accepted":true}`)}
	if err := service.Report(context.Background(), collector, id, acked); err != nil {
		t.Fatal(err)
	}
	if err := service.Report(context.Background(), collector, id, acked); err != nil {
		t.Fatalf("idempotent ack: %v", err)
	}
	recovered, err := service.Poll(context.Background(), collector, 0)
	if err != nil || len(recovered) != 1 || recovered[0].ID != id {
		t.Fatalf("acked request was not recoverable: items=%+v err=%v", recovered, err)
	}
	if err := service.Report(context.Background(), collector, id, ResultRequest{Status: "done", Result: json.RawMessage(`{"paused":true}`)}); err != nil {
		t.Fatal(err)
	}
	if err := service.Report(context.Background(), collector, id, acked); err == nil {
		t.Fatal("terminal request transitioned back to acked")
	} else if status, code := controlAPIError(err); status != 409 || code != "request_state_conflict" {
		t.Fatalf("unexpected transition error: %v", err)
	}
	if err := service.Report(context.Background(), collector, id, ResultRequest{Status: "done", Result: json.RawMessage(`{"paused":false}`)}); err == nil {
		t.Fatal("terminal result was overwritten")
	}
}

func TestDeleteLocalClassPayloadValidation(t *testing.T) {
	for _, class := range []string{"body", "pcap", "tls_secrets"} {
		payload := json.RawMessage(`{"recording_id":"run-a#0000","class":"` + class + `"}`)
		if err := validateRequestPayload("delete_local", payload); err != nil {
			t.Fatalf("valid class %q was rejected: %v", class, err)
		}
	}
	for _, payload := range []json.RawMessage{
		json.RawMessage(`{"recording_id":"run-a#0000","class":"tls_keys"}`),
		json.RawMessage(`{"recording_id":"run-a#0000","class":7}`),
	} {
		if err := validateRequestPayload("delete_local", payload); err == nil {
			t.Fatalf("invalid class payload was accepted: %s", payload)
		}
	}
}

func TestRecordingControlRequestsRequireOwnedActiveRun(t *testing.T) {
	db := controlTestDB(t)
	service := &Service{DB: db}
	project := controlPrincipal(t, db)
	registered, err := service.Register(context.Background(), project, RegisterRequest{
		Name: "iorec", Version: "iorec/0.1.0", Hostname: "redacted", OS: "linux/x86_64", Capabilities: validCapabilities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := service.Register(context.Background(), project, RegisterRequest{
		Name: "other", Version: "iorec/0.1.0", Hostname: "redacted", OS: "linux/x86_64", Capabilities: validCapabilities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	user := project
	user.Kind = auth.KindUser
	user.Role = auth.RoleOperator
	user.Subject = "operator@example.test"
	run := "run-control-" + uuid.NewString()[:8]
	recording := run + "#0000"
	if _, err := db.Pool.Exec(context.Background(), `insert into capture_runs(id,project_id,collector_id) values($1,$2,$3)`, run, project.ProjectID, registered.CollectorID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `insert into recordings(id,project_id,capture_run_id) values($1,$2,$3)`, recording, project.ProjectID, run); err != nil {
		t.Fatal(err)
	}
	request := CreateRequest{CollectorID: registered.CollectorID, Type: "backfill", Payload: json.RawMessage(`{"recording_id":"` + recording + `","first_seq":1,"last_seq":1}`)}
	if _, err := service.CreateCollectorRequest(context.Background(), user, request); err != nil {
		t.Fatalf("owned active recording request rejected: %v", err)
	}
	request.CollectorID = other.CollectorID
	if _, err := service.CreateCollectorRequest(context.Background(), user, request); err == nil {
		t.Fatal("request for a recording owned by another collector was accepted")
	}
	if _, err := db.Pool.Exec(context.Background(), `update capture_runs set state='deleting' where id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(context.Background(), `update recordings set state='deleting' where id=$1`, recording); err != nil {
		t.Fatal(err)
	}
	request.CollectorID = registered.CollectorID
	if _, err := service.CreateCollectorRequest(context.Background(), user, request); err == nil {
		t.Fatal("backfill was accepted after deletion started")
	}
	request.Type = "delete_local"
	request.Payload = json.RawMessage(`{"recording_id":"` + recording + `"}`)
	if _, err := service.CreateCollectorRequest(context.Background(), user, request); err != nil {
		t.Fatalf("local erasure was blocked after remote deletion started: %v", err)
	}
}

func TestProjectAndCollectorConfigurationVersionsMergeAndRemainIsolated(t *testing.T) {
	db := controlTestDB(t)
	service := &Service{DB: db}
	project := controlPrincipal(t, db)
	operator := project
	operator.Kind = auth.KindUser
	operator.Role = auth.RoleOperator
	operator.Subject = "config-operator@example.test"
	request := RegisterRequest{
		Name:         "iorec",
		Version:      "iorec/0.1.0",
		Hostname:     "redacted",
		OS:           "linux/x86_64",
		Capabilities: validCapabilities(),
	}
	first, err := service.Register(context.Background(), project, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Register(context.Background(), project, request)
	if err != nil {
		t.Fatal(err)
	}

	projectVersion, err := service.SetProjectConfig(context.Background(), operator, ConfigUpdate{
		Config: json.RawMessage(`{"content_policy":{"max_body_bytes":8192},"upload":{"batch_max_age_ms":4000}}`),
	})
	if err != nil || projectVersion != 1 {
		t.Fatalf("project config version=%d err=%v", projectVersion, err)
	}
	firstEffective, err := service.SetCollectorConfig(context.Background(), operator, first.CollectorID, ConfigUpdate{
		Config: json.RawMessage(`{"content_policy":{"capture_bodies":false}}`),
	})
	if err != nil || firstEffective.ConfigVersion != 2 {
		t.Fatalf("collector config response=%+v err=%v", firstEffective, err)
	}
	var merged map[string]any
	if err := json.Unmarshal(firstEffective.Config, &merged); err != nil {
		t.Fatal(err)
	}
	content := merged["content_policy"].(map[string]any)
	if content["capture_bodies"] != false || content["max_body_bytes"] != float64(8192) {
		t.Fatalf("collector override did not deep-merge project config: %s", firstEffective.Config)
	}
	if merged["config_version"] != float64(2) || merged["scope"].(map[string]any)["collector"] != first.CollectorID.String() {
		t.Fatalf("effective scope/version missing: %s", firstEffective.Config)
	}

	collectorPrincipal := project
	collectorPrincipal.CollectorID = first.CollectorID
	heartbeat, err := service.Heartbeat(context.Background(), collectorPrincipal, first.CollectorID, HeartbeatRequest{Status: "healthy"})
	if err != nil || heartbeat["config_version"] != int64(2) {
		t.Fatalf("heartbeat did not expose override revision: response=%+v err=%v", heartbeat, err)
	}

	projectVersion, err = service.SetProjectConfig(context.Background(), operator, ConfigUpdate{
		Config: json.RawMessage(`{"content_policy":{"max_body_bytes":4096}}`),
	})
	if err != nil || projectVersion != 3 {
		t.Fatalf("project revision did not advance beyond override: version=%d err=%v", projectVersion, err)
	}
	request.CollectorID = &first.CollectorID
	reregistered, err := service.Register(context.Background(), collectorPrincipal, request)
	if err != nil || reregistered.ConfigVersion != 3 {
		t.Fatalf("re-register after project update: response=%+v err=%v", reregistered, err)
	}
	if err := json.Unmarshal(reregistered.Config, &merged); err != nil {
		t.Fatal(err)
	}
	content = merged["content_policy"].(map[string]any)
	if content["capture_bodies"] != false || content["max_body_bytes"] != float64(4096) {
		t.Fatalf("project revision did not preserve narrower override: %s", reregistered.Config)
	}

	cleared, err := service.ClearCollectorConfig(context.Background(), operator, first.CollectorID)
	if err != nil || cleared.ConfigVersion != 4 {
		t.Fatalf("clear override response=%+v err=%v", cleared, err)
	}
	if err := json.Unmarshal(cleared.Config, &merged); err != nil {
		t.Fatal(err)
	}
	if merged["content_policy"].(map[string]any)["capture_bodies"] != true {
		t.Fatalf("clear did not restore project/default configuration: %s", cleared.Config)
	}

	otherProject := controlPrincipal(t, db)
	otherOperator := otherProject
	otherOperator.Kind = auth.KindUser
	otherOperator.Role = auth.RoleOperator
	if _, err := service.SetCollectorConfig(context.Background(), otherOperator, second.CollectorID, ConfigUpdate{Config: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("cross-project collector configuration update was accepted")
	} else if status, code := controlAPIError(err); status != 404 || code != "collector_not_found" {
		t.Fatalf("unexpected cross-project error: %v", err)
	}

	var audits int
	if err := db.Pool.QueryRow(context.Background(), `select count(*) from audit_log where project_id=$1 and action like 'collector_config.%'`, project.ProjectID).Scan(&audits); err != nil || audits != 4 {
		t.Fatalf("configuration audit count=%d err=%v", audits, err)
	}
}

func TestConfigurationRejectsPlatformOwnedAndOvercomplexDocuments(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`[]`),
		json.RawMessage(`{"config_version":9}`),
		json.RawMessage(`{"scope":{}}`),
	} {
		if _, err := configObject(raw, true); err == nil {
			t.Fatalf("invalid configuration was accepted: %s", raw)
		}
	}
	deep := `{"a":` + strings.Repeat(`{"a":`, maxConfigDepth+1) + `true` + strings.Repeat(`}`, maxConfigDepth+2)
	if _, err := configObject(json.RawMessage(deep), true); err == nil {
		t.Fatal("overly deep configuration was accepted")
	}
}
