// Package control implements the collector management protocol (platform/09):
// registration, capabilities, heartbeat, versioned config, collector requests.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/notify"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/store"
)

// Service holds dependencies.
type Service struct{ DB *store.DB }

// SessionTTL of collector session tokens.
const SessionTTL = time.Hour

// RegisterRequest is POST /collectors:register.
type RegisterRequest struct {
	CollectorID  *uuid.UUID      `json:"collector_id,omitempty"` // re-register existing
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Capabilities json.RawMessage `json:"capabilities"`
}

// RegisterResponse returns the session token and config.
type RegisterResponse struct {
	CollectorID   uuid.UUID       `json:"collector_id"`
	SessionToken  string          `json:"session_token"`
	ExpiresAt     time.Time       `json:"expires_at"`
	ConfigVersion int64           `json:"config_version"`
	Config        json.RawMessage `json:"config"`
}

// Register creates or refreshes a collector using a project or collector credential.
func (s *Service) Register(ctx context.Context, p auth.Principal, req RegisterRequest) (*RegisterResponse, error) {
	if req.Name == "" || len(req.Name) > 256 || req.Version == "" || len(req.Version) > 256 ||
		req.Hostname == "" || len(req.Hostname) > 1<<10 || req.OS == "" || len(req.OS) > 256 ||
		strings.ContainsAny(req.Name, "\x00\r\n") || strings.ContainsAny(req.Version, "\x00\r\n") ||
		strings.ContainsAny(req.Hostname, "\x00\r\n") || strings.ContainsAny(req.OS, "\x00\r\n") {
		return nil, httpapi.E(400, "malformed_request", "collector identity is invalid")
	}
	if req.CollectorID != nil && p.CollectorID != uuid.Nil && *req.CollectorID != p.CollectorID {
		return nil, httpapi.E(http.StatusForbidden, "forbidden", "collector session cannot re-register another collector")
	}
	if len(req.Capabilities) == 0 {
		return nil, httpapi.E(400, "malformed_request", "capabilities required")
	}
	var generic any
	if err := json.Unmarshal(req.Capabilities, &generic); err != nil {
		return nil, httpapi.E(400, "malformed_request", "capabilities not JSON")
	}
	if err := protocol.Validate(protocol.SchemaCapabilitiesV1, generic); err != nil {
		return nil, httpapi.E(400, "malformed_request", "capabilities schema: "+err.Error())
	}
	tok := auth.NewToken("iorc_")
	exp := time.Now().Add(SessionTTL)
	resp := &RegisterResponse{SessionToken: tok, ExpiresAt: exp}
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		id := uuid.New()
		if req.CollectorID != nil {
			id = *req.CollectorID
		} else if p.CollectorID != uuid.Nil {
			id = p.CollectorID
		}
		var existingProject uuid.UUID
		err := tx.QueryRow(ctx, `select project_id from collectors where id=$1`, id).Scan(&existingProject)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx, `insert into collectors(id, project_id, name, version, hostname, os, capabilities, session_token_hash, session_expires_at, last_heartbeat_at, status) values($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),'online')`,
				id, p.ProjectID, req.Name, req.Version, req.Hostname, req.OS, req.Capabilities, auth.HashToken(tok), exp); err != nil {
				return err
			}
		case err != nil:
			return err
		case existingProject != p.ProjectID:
			return httpapi.E(http.StatusForbidden, "forbidden", "collector belongs to another project")
		default:
			if _, err := tx.Exec(ctx, `update collectors set name=$2, version=$3, hostname=$4, os=$5, capabilities=$6, session_token_hash=$7, session_expires_at=$8, last_heartbeat_at=now(), status='online' where id=$1`,
				id, req.Name, req.Version, req.Hostname, req.OS, req.Capabilities, auth.HashToken(tok), exp); err != nil {
				return err
			}
		}
		resp.CollectorID = id
		cfg, ver, err := s.effectiveConfig(ctx, tx, p.ProjectID, id)
		if err != nil {
			return err
		}
		resp.Config, resp.ConfigVersion = cfg, ver
		return notify.Publish(ctx, tx, p.ProjectID, "collector", id.String(), "registered", 0)
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

const (
	maxConfigBytes = 256 << 10
	maxConfigDepth = 32
	maxConfigNodes = 10_000
)

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ConfigUpdate replaces one project default or collector override document.
// The supplied object may be partial; defaults and narrower scope are merged
// recursively when a collector registers.
type ConfigUpdate struct {
	Config json.RawMessage `json:"config"`
}

// ConfigResponse is the effective, versioned document after an update.
type ConfigResponse struct {
	ConfigVersion int64           `json:"config_version"`
	Config        json.RawMessage `json:"config"`
}

// Config documents live in projects.settings->collector_config and an
// optional collectors.config_override. Every update chooses a revision above
// both scopes, so heartbeat version comparisons remain unambiguous.
func (s *Service) effectiveConfig(ctx context.Context, tx pgx.Tx, project, collector uuid.UUID) (json.RawMessage, int64, error) {
	return s.effectiveConfigFrom(ctx, tx, project, collector)
}

func (s *Service) effectiveConfigFrom(ctx context.Context, q queryRower, project, collector uuid.UUID) (json.RawMessage, int64, error) {
	var settings json.RawMessage
	var override json.RawMessage
	var overrideVersion int64
	if err := q.QueryRow(ctx, `select p.settings, coalesce(c.config_override,'null'::jsonb), c.config_override_version
		from projects p join collectors c on c.project_id=p.id where p.id=$1 and c.id=$2`, project, collector).Scan(&settings, &override, &overrideVersion); err != nil {
		return nil, 0, err
	}
	var st struct {
		CollectorConfig json.RawMessage `json:"collector_config"`
		ConfigVersion   int64           `json:"collector_config_version"`
	}
	if err := json.Unmarshal(settings, &st); err != nil || st.ConfigVersion < 0 {
		return nil, 0, fmt.Errorf("project collector configuration is invalid")
	}
	base, err := configObject(json.RawMessage(DefaultConfig), false)
	if err != nil {
		return nil, 0, err
	}
	if len(st.CollectorConfig) > 0 && string(st.CollectorConfig) != "null" {
		projectConfig, err := configObject(st.CollectorConfig, true)
		if err != nil {
			return nil, 0, fmt.Errorf("project collector configuration: %w", err)
		}
		mergeConfig(base, projectConfig)
	}
	if len(override) > 0 && string(override) != "null" {
		collectorConfig, err := configObject(override, true)
		if err != nil {
			return nil, 0, fmt.Errorf("collector configuration override: %w", err)
		}
		mergeConfig(base, collectorConfig)
	}
	version := max(st.ConfigVersion, overrideVersion)
	base["config_version"] = version
	base["scope"] = map[string]any{"project": project.String(), "collector": collector.String()}
	encoded, err := json.Marshal(base)
	if err != nil {
		return nil, 0, err
	}
	return encoded, version, nil
}

func configObject(raw json.RawMessage, partial bool) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxConfigBytes || !json.Valid(raw) {
		return nil, httpapi.E(400, "malformed_config", "configuration must be bounded valid JSON")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, httpapi.E(400, "malformed_config", "configuration is not valid JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, httpapi.E(400, "malformed_config", "configuration must be an object")
	}
	if err := validateConfigTree(object, 0, new(int)); err != nil {
		return nil, err
	}
	if !partial && len(object) == 0 {
		return nil, httpapi.E(400, "malformed_config", "configuration must not be empty")
	}
	for key := range object {
		if key == "scope" || key == "config_version" {
			return nil, httpapi.E(400, "malformed_config", "scope and config_version are platform-owned")
		}
	}
	return object, nil
}

func validateConfigTree(value any, depth int, nodes *int) error {
	*nodes++
	if depth > maxConfigDepth || *nodes > maxConfigNodes {
		return httpapi.E(400, "malformed_config", "configuration exceeds complexity limits")
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "" || len(key) > 256 || strings.ContainsAny(key, "\x00\r\n") {
				return httpapi.E(400, "malformed_config", "configuration contains an invalid key")
			}
			if err := validateConfigTree(child, depth+1, nodes); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := validateConfigTree(child, depth+1, nodes); err != nil {
				return err
			}
		}
	case string:
		if len(typed) > maxConfigBytes || strings.ContainsRune(typed, '\x00') {
			return httpapi.E(400, "malformed_config", "configuration contains an invalid string")
		}
	case nil, bool, float64:
	default:
		return httpapi.E(400, "malformed_config", "configuration contains an unsupported value")
	}
	return nil
}

func mergeConfig(base, override map[string]any) {
	for key, incoming := range override {
		incomingObject, incomingIsObject := incoming.(map[string]any)
		baseObject, baseIsObject := base[key].(map[string]any)
		if incomingIsObject && baseIsObject {
			mergeConfig(baseObject, incomingObject)
			continue
		}
		base[key] = incoming
	}
}

func requireConfigOperator(p auth.Principal) error {
	if p.Kind != auth.KindUser || !p.HasRole(auth.RoleOperator) {
		return httpapi.E(http.StatusForbidden, "forbidden", "operator role required")
	}
	return nil
}

// SetProjectConfig replaces the project default and advances beyond every
// narrower collector revision so all connected collectors observe the change.
func (s *Service) SetProjectConfig(ctx context.Context, p auth.Principal, update ConfigUpdate) (int64, error) {
	if err := requireConfigOperator(p); err != nil {
		return 0, err
	}
	config, err := configObject(update.Config, true)
	if err != nil {
		return 0, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return 0, err
	}
	var version int64
	err = s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var projectVersion, collectorVersion int64
		if err := tx.QueryRow(ctx, `select coalesce((settings->>'collector_config_version')::bigint,0) from projects where id=$1 for update`, p.ProjectID).Scan(&projectVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(http.StatusNotFound, "project_not_found", "project does not exist")
			}
			return err
		}
		if err := tx.QueryRow(ctx, `select coalesce(max(config_override_version),0) from collectors where project_id=$1`, p.ProjectID).Scan(&collectorVersion); err != nil {
			return err
		}
		current := max(projectVersion, collectorVersion)
		if current == int64(1<<63-1) {
			return httpapi.E(http.StatusConflict, "config_version_exhausted", "configuration revision is exhausted")
		}
		version = current + 1
		if _, err := tx.Exec(ctx, `update projects set settings=jsonb_set(jsonb_set(settings,'{collector_config}',$2::jsonb,true),'{collector_config_version}',to_jsonb($3::bigint),true) where id=$1`, p.ProjectID, encoded, version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'collector_config.project_update','project',$3,jsonb_build_object('config_version',$4::bigint))`, p.ProjectID, p.Subject, p.ProjectID.String(), version); err != nil {
			return err
		}
		return notify.Publish(ctx, tx, p.ProjectID, "project", p.ProjectID.String(), "collector_config", version)
	})
	return version, err
}

// SetCollectorConfig replaces one narrower override and returns the resulting
// merged document. A project update later advances beyond this revision.
func (s *Service) SetCollectorConfig(ctx context.Context, p auth.Principal, collector uuid.UUID, update ConfigUpdate) (*ConfigResponse, error) {
	if err := requireConfigOperator(p); err != nil {
		return nil, err
	}
	config, err := configObject(update.Config, true)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return s.replaceCollectorConfig(ctx, p, collector, encoded, "collector_config.collector_update")
}

// ClearCollectorConfig removes the narrower override while still advancing
// the revision so a connected collector re-applies the project document.
func (s *Service) ClearCollectorConfig(ctx context.Context, p auth.Principal, collector uuid.UUID) (*ConfigResponse, error) {
	if err := requireConfigOperator(p); err != nil {
		return nil, err
	}
	return s.replaceCollectorConfig(ctx, p, collector, nil, "collector_config.collector_clear")
}

func (s *Service) replaceCollectorConfig(ctx context.Context, p auth.Principal, collector uuid.UUID, encoded []byte, action string) (*ConfigResponse, error) {
	var response ConfigResponse
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var projectVersion, collectorVersion int64
		if err := tx.QueryRow(ctx, `select coalesce((p.settings->>'collector_config_version')::bigint,0), c.config_override_version
			from collectors c join projects p on p.id=c.project_id where c.id=$1 and c.project_id=$2 for update of c`, collector, p.ProjectID).Scan(&projectVersion, &collectorVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(http.StatusNotFound, "collector_not_found", "collector does not exist in this project")
			}
			return err
		}
		current := max(projectVersion, collectorVersion)
		if current == int64(1<<63-1) {
			return httpapi.E(http.StatusConflict, "config_version_exhausted", "configuration revision is exhausted")
		}
		version := current + 1
		if _, err := tx.Exec(ctx, `update collectors set config_override=$3::jsonb,config_override_version=$4 where id=$1 and project_id=$2`, collector, p.ProjectID, encoded, version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,$3,'collector',$4,jsonb_build_object('config_version',$5::bigint))`, p.ProjectID, p.Subject, action, collector.String(), version); err != nil {
			return err
		}
		config, effectiveVersion, err := s.effectiveConfigFrom(ctx, tx, p.ProjectID, collector)
		if err != nil {
			return err
		}
		response = ConfigResponse{ConfigVersion: effectiveVersion, Config: config}
		return notify.Publish(ctx, tx, p.ProjectID, "collector", collector.String(), "config", version)
	})
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// DefaultConfig is the project default when none is set (platform/09 §4).
const DefaultConfig = `{
  "content_policy": {"capture_bodies": true, "max_body_bytes": 1048576, "redact_fields": ["authorization","x-api-key","cookie","proxy-authorization"], "pty": false},
  "upload": {"batch_max_bytes": 4194304, "batch_max_age_ms": 5000, "rate_limit_bytes_per_s": 5242880},
  "sensitive_tier_upload": {"pcap": false, "tls_keys": false},
  "retention_local": {"acked_events_ttl_hours": 168, "body_ttl_hours": 72, "pcap_ttl_hours": 24, "tls_secrets_ttl_hours": 24},
  "egress_classification": {"model_hosts": ["api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","api.fireworks.ai","openrouter.ai"], "ignore_hosts": []}
}`

// HeartbeatRequest is POST /collectors/{id}:heartbeat.
type HeartbeatRequest struct {
	Status          string          `json:"status"`
	ActiveRuns      int             `json:"active_runs"`
	SpoolBytesUsed  int64           `json:"spool_bytes_used"`
	AckedLagSeconds float64         `json:"acked_lag_seconds"`
	LastError       *string         `json:"last_error"`
	ConfigVersion   int64           `json:"config_version"`
	EffectiveConfig json.RawMessage `json:"effective_config,omitempty"`
	RejectedConfig  json.RawMessage `json:"rejected,omitempty"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
}

// Heartbeat updates health; returns pending config version and refreshed session expiry.
func (s *Service) Heartbeat(ctx context.Context, p auth.Principal, id uuid.UUID, req HeartbeatRequest) (map[string]any, error) {
	if p.CollectorID != id {
		return nil, httpapi.E(403, "forbidden", "heartbeat for another collector")
	}
	if req.Status != "healthy" && req.Status != "degraded" && req.Status != "error" ||
		req.ActiveRuns < 0 || req.SpoolBytesUsed < 0 || req.AckedLagSeconds < 0 || req.ConfigVersion < 0 {
		return nil, httpapi.E(400, "malformed_request", "collector health is invalid")
	}
	if len(req.Capabilities) > 0 {
		var generic any
		if err := json.Unmarshal(req.Capabilities, &generic); err != nil {
			return nil, httpapi.E(400, "malformed_request", "capabilities not JSON")
		}
		if err := protocol.Validate(protocol.SchemaCapabilitiesV1, generic); err != nil {
			return nil, httpapi.E(400, "malformed_request", "capabilities schema: "+err.Error())
		}
	}
	health, _ := json.Marshal(req)
	exp := time.Now().Add(SessionTTL)
	var eff any
	if len(req.EffectiveConfig) > 0 {
		eff = req.EffectiveConfig
	}
	var caps any
	if len(req.Capabilities) > 0 {
		caps = req.Capabilities
	}
	_, err := s.DB.Pool.Exec(ctx, `update collectors set last_heartbeat_at=now(), health=$2, status='online', config_version=$3, effective_config=coalesce($4::jsonb, effective_config), capabilities=coalesce($5::jsonb, capabilities), session_expires_at=$6 where id=$1`,
		id, health, req.ConfigVersion, eff, caps, exp)
	if err != nil {
		return nil, err
	}
	_, version, err := s.effectiveConfigFrom(ctx, s.DB.Pool, p.ProjectID, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"config_version": version, "session_expires_at": exp}, nil
}

// StaleAfter / OfflineAfter thresholds.
const (
	StaleAfter   = 90 * time.Second
	OfflineAfter = 10 * time.Minute
	// DeliveryLease bounds the interval after which work delivered to a
	// collector but not ACKed may be offered again. ACKed work is also returned
	// so a restarted collector can finish an idempotent operation and report its
	// terminal result.
	DeliveryLease = 60 * time.Second
)

// SweepStatus marks stale/offline collectors and auto-seals recordings of offline collectors past the window.
func (s *Service) SweepStatus(ctx context.Context, autoSealAfter time.Duration) error {
	if _, err := s.DB.Pool.Exec(ctx, `update collectors set status = case when last_heartbeat_at < now() - $1::interval then 'offline' when last_heartbeat_at < now() - $2::interval then 'stale' else 'online' end where status <> 'revoked'`, OfflineAfter, StaleAfter); err != nil {
		return err
	}
	// auto-seal open recordings with no batches for autoSealAfter (platform/04 §7)
	_, err := s.DB.Pool.Exec(ctx, `update recordings r set state='sealed', sealed_at=now(), integrity_alerts = integrity_alerts || jsonb_build_array(jsonb_build_object('kind','auto_sealed_incomplete','at',now())), updated_at=now()
		where r.state='open' and r.updated_at < now() - $1::interval`, autoSealAfter)
	return err
}

// CreateRequest is POST /collector-requests (users).
type CreateRequest struct {
	CollectorID uuid.UUID       `json:"collector_id"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	ExpiresIn   int             `json:"expires_in_seconds,omitempty"`
}

var allowedRequestTypes = map[string]bool{"backfill": true, "apply_config": true, "pause": true, "resume": true, "flush": true, "seal": true, "upload_sensitive": true, "delete_local": true}

const (
	maxRequestPayloadBytes = 64 << 10
	maxRequestReasonBytes  = 2 << 10
	minRequestExpiry       = 60
	maxRequestExpiry       = 7 * 24 * 60 * 60
)

func validRequestID(value string) bool {
	return value != "" && len(value) <= 240 && !strings.ContainsAny(value, "\x00\r\n")
}

func validateRequestPayload(kind string, raw json.RawMessage) error {
	if len(raw) > maxRequestPayloadBytes || !json.Valid(raw) {
		return httpapi.E(400, "malformed_request", "request payload must be valid bounded JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return httpapi.E(400, "malformed_request", "request payload must be a JSON object")
	}
	recordingID := func(required bool) error {
		var value string
		if field, ok := object["recording_id"]; ok {
			if err := json.Unmarshal(field, &value); err != nil || !validRequestID(value) {
				return httpapi.E(400, "malformed_request", "payload.recording_id is invalid")
			}
		} else if required {
			return httpapi.E(400, "malformed_request", "payload.recording_id is required")
		}
		return nil
	}
	switch kind {
	case "backfill":
		var payload struct {
			RecordingID string `json:"recording_id"`
			FirstSeq    int64  `json:"first_seq"`
			LastSeq     int64  `json:"last_seq"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil || !validRequestID(payload.RecordingID) || payload.FirstSeq < 1 || payload.LastSeq < payload.FirstSeq {
			return httpapi.E(400, "malformed_request", "backfill payload has an invalid recording or sequence range")
		}
	case "apply_config":
		var payload struct {
			ConfigVersion *int64 `json:"config_version"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil || payload.ConfigVersion == nil || *payload.ConfigVersion < 0 {
			return httpapi.E(400, "malformed_request", "apply_config requires a non-negative config_version")
		}
	case "flush", "seal":
		if err := recordingID(true); err != nil {
			return err
		}
	case "delete_local":
		if err := recordingID(true); err != nil {
			return err
		}
		if field, ok := object["class"]; ok {
			var class string
			if err := json.Unmarshal(field, &class); err != nil || (class != "body" && class != "pcap" && class != "tls_secrets") {
				return httpapi.E(400, "malformed_request", "payload.class must be body, pcap, or tls_secrets")
			}
		}
	case "pause", "resume":
		if field, ok := object["reason"]; ok {
			var reason string
			if err := json.Unmarshal(field, &reason); err != nil || len(reason) > maxRequestReasonBytes || strings.ContainsAny(reason, "\x00\r\n") {
				return httpapi.E(400, "malformed_request", "payload.reason is invalid")
			}
		}
	case "upload_sensitive":
		var payload struct {
			RecordingID string   `json:"recording_id"`
			ApprovalID  string   `json:"approval_id"`
			Kinds       []string `json:"kinds"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil || !validRequestID(payload.RecordingID) {
			return httpapi.E(400, "malformed_request", "upload_sensitive requires a valid recording_id")
		}
		if payload.ApprovalID == "" || len(payload.ApprovalID) > 256 || strings.ContainsAny(payload.ApprovalID, "\x00\r\n") {
			return httpapi.E(400, "approval_required", "upload_sensitive requires a bounded payload.approval_id")
		}
		if len(payload.Kinds) == 0 || len(payload.Kinds) > 2 {
			return httpapi.E(400, "malformed_request", "upload_sensitive requires one or two sensitive kinds")
		}
		seen := map[string]bool{}
		for _, value := range payload.Kinds {
			if value != "pcap" && value != "tls_keys" || seen[value] {
				return httpapi.E(400, "malformed_request", "sensitive kind must be unique pcap or tls_keys")
			}
			seen[value] = true
		}
	}
	return nil
}

// CreateCollectorRequest enqueues a request for a collector.
func (s *Service) CreateCollectorRequest(ctx context.Context, p auth.Principal, req CreateRequest) (uuid.UUID, error) {
	if !allowedRequestTypes[req.Type] {
		return uuid.Nil, httpapi.E(400, "malformed_request", "unknown request type")
	}
	if len(req.Payload) == 0 {
		req.Payload = json.RawMessage(`{}`)
	}
	if err := validateRequestPayload(req.Type, req.Payload); err != nil {
		return uuid.Nil, err
	}
	if req.ExpiresIn < 0 || req.ExpiresIn > 0 && (req.ExpiresIn < minRequestExpiry || req.ExpiresIn > maxRequestExpiry) {
		return uuid.Nil, httpapi.E(400, "malformed_request", "request expiry must be between 60 seconds and 7 days")
	}
	exp := time.Now().Add(24 * time.Hour)
	if req.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
	}
	id := uuid.New()
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var owner uuid.UUID
		if err := tx.QueryRow(ctx, `select project_id from collectors where id=$1`, req.CollectorID).Scan(&owner); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(404, "collector_not_found", "unknown collector")
			}
			return err
		}
		if owner != p.ProjectID {
			return httpapi.E(403, "forbidden", "collector belongs to another project")
		}
		if req.Type == "backfill" || req.Type == "flush" || req.Type == "seal" || req.Type == "upload_sensitive" || req.Type == "delete_local" {
			var target struct {
				RecordingID string `json:"recording_id"`
			}
			if err := json.Unmarshal(req.Payload, &target); err != nil {
				return httpapi.E(400, "malformed_request", "request payload is invalid")
			}
			var runState, recordingState string
			var runCollector *uuid.UUID
			err := tx.QueryRow(ctx, `select c.state,r.state,c.collector_id from recordings r join capture_runs c on c.id=r.capture_run_id and c.project_id=r.project_id where r.id=$1 and r.project_id=$2`, target.RecordingID, p.ProjectID).Scan(&runState, &recordingState, &runCollector)
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(404, "recording_not_found", "unknown recording in this project")
			}
			if err != nil {
				return err
			}
			if runCollector == nil || *runCollector != req.CollectorID {
				return httpapi.E(409, "collector_recording_conflict", "recording is not owned by the target collector")
			}
			if req.Type != "delete_local" && (runState != "active" || recordingState != "open" && recordingState != "sealed") {
				return httpapi.E(409, "recording_unavailable", "recording is deleting, deleted, or no longer has raw evidence")
			}
		}
		if _, err := tx.Exec(ctx, `insert into collector_requests(id, collector_id, project_id, type, payload, created_by, expires_at) values($1,$2,$3,$4,$5,$6,$7)`,
			id, req.CollectorID, p.ProjectID, req.Type, req.Payload, p.Subject, exp); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'collector_request.create','collector_request',$3,$4)`, p.ProjectID, p.Subject, id.String(), req.Payload); err != nil {
			return err
		}
		return notify.Publish(ctx, tx, p.ProjectID, "collector_request", id.String(), "created", 0)
	})
	return id, err
}

// PendingRequest is one item delivered to a collector.
type PendingRequest struct {
	ID        uuid.UUID       `json:"id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// Poll returns pending requests for the collector, waiting up to wait for one to appear.
func (s *Service) Poll(ctx context.Context, p auth.Principal, wait time.Duration) ([]PendingRequest, error) {
	deadline := time.Now().Add(wait)
	for {
		rows, err := s.DB.Pool.Query(ctx, `update collector_requests
			set status=case when status='acked' then 'acked' else 'delivered' end,
				delivered_at=now(), delivery_attempts=delivery_attempts+1
			where id in (
				select id from collector_requests
				where collector_id=$1
				  and (status='acked'
				       or (expires_at is null or expires_at > now())
				          and (status='pending'
				               or status='delivered' and delivered_at < now() - $2::interval))
				order by created_at limit 50 for update skip locked)
			returning id, type, payload, coalesce(expires_at, now()+interval '1 day')`, p.CollectorID, DeliveryLease)
		if err != nil {
			return nil, err
		}
		var out []PendingRequest
		for rows.Next() {
			var pr PendingRequest
			if err := rows.Scan(&pr.ID, &pr.Type, &pr.Payload, &pr.ExpiresAt); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, pr)
		}
		rows.Close()
		if len(out) > 0 || time.Now().After(deadline) {
			if out == nil {
				out = []PendingRequest{}
			}
			return out, nil
		}
		select {
		case <-ctx.Done():
			return []PendingRequest{}, nil
		case <-time.After(time.Second):
		}
	}
}

// ResultRequest is POST /collector-requests/{id}:result.
type ResultRequest struct {
	Status string          `json:"status"` // acked|done|rejected
	Reason string          `json:"reason,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Report stores the collector's outcome.
func (s *Service) Report(ctx context.Context, p auth.Principal, id uuid.UUID, req ResultRequest) error {
	if req.Status != "acked" && req.Status != "done" && req.Status != "rejected" {
		return httpapi.E(400, "malformed_request", "status must be acked|done|rejected")
	}
	if len(req.Reason) > maxRequestReasonBytes || strings.ContainsAny(req.Reason, "\x00\r\n") {
		return httpapi.E(400, "malformed_request", "result reason is invalid")
	}
	if len(req.Result) > maxRequestPayloadBytes || len(req.Result) > 0 && !json.Valid(req.Result) {
		return httpapi.E(400, "malformed_request", "result must be valid bounded JSON")
	}
	res := map[string]any{"reason": req.Reason}
	if len(req.Result) > 0 {
		res["result"] = req.Result
	}
	rb, _ := json.Marshal(res)
	finished := req.Status != "acked"
	return s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var current string
		var existing json.RawMessage
		err := tx.QueryRow(ctx, `select status, coalesce(result,'null'::jsonb) from collector_requests where id=$1 and collector_id=$2 for update`, id, p.CollectorID).Scan(&current, &existing)
		if errors.Is(err, pgx.ErrNoRows) {
			return httpapi.E(404, "request_not_found", "unknown request for this collector")
		}
		if err != nil {
			return err
		}
		if current == req.Status {
			var oldValue, newValue any
			if json.Unmarshal(existing, &oldValue) == nil && json.Unmarshal(rb, &newValue) == nil && reflect.DeepEqual(oldValue, newValue) {
				return nil
			}
			return httpapi.E(409, "request_state_conflict", "request status was already reported with a different result")
		}
		allowed := current == "delivered" || current == "acked" && req.Status != "acked"
		if !allowed {
			return httpapi.E(409, "request_state_conflict", "request cannot transition from "+current+" to "+req.Status)
		}
		if _, err := tx.Exec(ctx, `update collector_requests set status=$3, result=$4, finished_at = case when $5 then now() else finished_at end where id=$1 and collector_id=$2`, id, p.CollectorID, req.Status, rb, finished); err != nil {
			return err
		}
		return notify.Publish(ctx, tx, p.ProjectID, "collector_request", id.String(), req.Status, 0)
	})
}

// ExpireRequests marks stale pending/delivered requests expired.
func (s *Service) ExpireRequests(ctx context.Context) error {
	_, err := s.DB.Pool.Exec(ctx, `update collector_requests set status='expired', finished_at=now() where status in ('pending','delivered') and expires_at < now()`)
	return err
}
