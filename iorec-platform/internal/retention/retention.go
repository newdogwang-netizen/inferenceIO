// Package retention implements durable remote erasure, local-delete
// propagation, and project retention policy enforcement.
package retention

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/notify"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/store"
)

const (
	DefaultRawEvidenceDays = 90
	DefaultMetadataDays    = 365
	maxRetentionDays       = 3650
	maxDeleteReasonBytes   = 2048
	objectDeleteBatch      = 100
	staleBlobUploadGrace   = 24 * time.Hour
)

// Policy is stored under projects.settings.retention. Metadata retention must
// never be shorter than raw-evidence retention.
type Policy struct {
	RawEvidenceDays int `json:"raw_evidence_days"`
	MetadataDays    int `json:"metadata_days"`
}

// DefaultPolicy returns the documented platform defaults.
func DefaultPolicy() Policy {
	return Policy{RawEvidenceDays: DefaultRawEvidenceDays, MetadataDays: DefaultMetadataDays}
}

func (p Policy) validate() error {
	if p.RawEvidenceDays < 1 || p.RawEvidenceDays > maxRetentionDays ||
		p.MetadataDays < p.RawEvidenceDays || p.MetadataDays > maxRetentionDays {
		return httpapi.E(http.StatusBadRequest, "malformed_retention_policy", "retention days must satisfy 1 <= raw_evidence_days <= metadata_days <= 3650")
	}
	return nil
}

// PolicyFromSettings parses project settings and fails closed to the shorter
// documented defaults if an older or manually edited document is malformed.
func PolicyFromSettings(raw []byte) Policy {
	policy := DefaultPolicy()
	var settings struct {
		Retention *Policy `json:"retention"`
	}
	if json.Unmarshal(raw, &settings) == nil && settings.Retention != nil && settings.Retention.validate() == nil {
		policy = *settings.Retention
	}
	return policy
}

// Service owns the deletion state machine.
type Service struct {
	DB  *store.DB
	Obj objstore.Store
}

// DeleteRequest requires an exact confirmation to protect an irreversible API.
type DeleteRequest struct {
	Confirmation string `json:"confirmation"`
	Reason       string `json:"reason,omitempty"`
}

// Status is the externally visible state of one deletion request.
type Status struct {
	ID                  uuid.UUID  `json:"id"`
	RequestedEntityType string     `json:"requested_entity_type"`
	RequestedEntityID   string     `json:"requested_entity_id"`
	CaptureRunID        string     `json:"capture_run_id"`
	Mode                string     `json:"mode"`
	RecordingID         *string    `json:"recording_id,omitempty"`
	CollectorRequestID  *uuid.UUID `json:"collector_request_id,omitempty"`
	CollectorStatus     *string    `json:"collector_status,omitempty"`
	State               string     `json:"state"`
	Attempts            int        `json:"attempts"`
	ObjectTotal         int        `json:"object_total"`
	ObjectsDeleted      int        `json:"objects_deleted"`
	LastError           *string    `json:"last_error,omitempty"`
	RequestedBy         string     `json:"requested_by"`
	Reason              *string    `json:"reason,omitempty"`
	RequestedAt         time.Time  `json:"requested_at"`
	RemoteDeletedAt     *time.Time `json:"remote_deleted_at,omitempty"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
}

func scanStatus(row pgx.Row) (*Status, error) {
	var out Status
	err := row.Scan(&out.ID, &out.RequestedEntityType, &out.RequestedEntityID,
		&out.CaptureRunID, &out.Mode, &out.RecordingID, &out.CollectorRequestID,
		&out.CollectorStatus, &out.State, &out.Attempts, &out.ObjectTotal, &out.ObjectsDeleted,
		&out.LastError, &out.RequestedBy, &out.Reason,
		&out.RequestedAt, &out.RemoteDeletedAt, &out.CompletedAt)
	return &out, err
}

const statusColumns = `id,requested_entity_type,requested_entity_id,capture_run_id,mode,recording_id,
	collector_request_id,(select status from collector_requests where id=deletion_requests.collector_request_id),
	state,attempts,(select count(*) from deletion_objects where deletion_request_id=deletion_requests.id),
	(select count(*) from deletion_objects where deletion_request_id=deletion_requests.id and state='done'),
	last_error,requested_by,reason,requested_at,remote_deleted_at,completed_at`

// DeleteHandler returns an admin-only handler for recording, capture_run, or session.
// Recording and session deletion conservatively erases their entire CaptureRun,
// because immutable raw batches can contain evidence from multiple logical scopes.
func (s *Service) DeleteHandler(entityType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := httpapi.RequireUser(r, auth.RoleAdmin)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		var req DeleteRequest
		if err := httpapi.DecodeJSON(r, &req, 8<<10); err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		id := chi.URLParam(r, "id")
		status, err := s.RequestDelete(r.Context(), p, entityType, id, req)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusAccepted, status)
	}
}

// Get returns one deletion request to an admin in the same project.
func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpapi.WriteError(w, r, httpapi.E(http.StatusBadRequest, "malformed_request", "bad deletion request id"))
		return
	}
	status, err := scanStatus(s.DB.Pool.QueryRow(r.Context(), `select `+statusColumns+` from deletion_requests where id=$1 and project_id=$2`, id, p.ProjectID))
	if errors.Is(err, pgx.ErrNoRows) {
		err = httpapi.E(http.StatusNotFound, "not_found", "unknown deletion request")
	}
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, status)
}

// List returns recent deletion requests to project admins.
func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	rows, err := s.DB.Pool.Query(r.Context(), `select `+statusColumns+` from deletion_requests where project_id=$1 order by requested_at desc limit 500`, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]Status, 0)
	for rows.Next() {
		status, err := scanStatus(rows)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		items = append(items, *status)
	}
	if err := rows.Err(); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// RetryLocal reissues a failed/rejected local erasure after an operator has
// corrected the collector's local policy. The replacement request never
// expires while the collector is offline.
func (s *Service) RetryLocal(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpapi.WriteError(w, r, httpapi.E(http.StatusBadRequest, "malformed_request", "bad deletion request id"))
		return
	}
	var collectorRequestID uuid.UUID
	err = s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		var state, run string
		var collector *uuid.UUID
		var recording *string
		if err := tx.QueryRow(r.Context(), `select state,capture_run_id,collector_id,recording_id from deletion_requests where id=$1 and project_id=$2 for update`, id, p.ProjectID).Scan(&state, &run, &collector, &recording); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(http.StatusNotFound, "not_found", "unknown deletion request")
			}
			return err
		}
		if state != "local_failed" || collector == nil || recording == nil {
			return httpapi.E(http.StatusConflict, "deletion_state_conflict", "only a failed propagated deletion can be retried")
		}
		collectorRequestID = uuid.New()
		payload, _ := json.Marshal(map[string]any{"recording_id": *recording, "capture_run_id": run, "reason": "platform_delete_retry"})
		if _, err := tx.Exec(r.Context(), `insert into collector_requests(id,collector_id,project_id,type,payload,status,created_by,expires_at) values($1,$2,$3,'delete_local',$4,'pending',$5,null)`, collectorRequestID, *collector, p.ProjectID, payload, p.Subject); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `update deletion_requests set collector_request_id=$2,state='local_pending',completed_at=null,last_error=null where id=$1`, id, collectorRequestID); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'retention.local_delete_retry','deletion_request',$3,jsonb_build_object('collector_request_id',$4::text))`, p.ProjectID, p.Subject, id.String(), collectorRequestID); err != nil {
			return err
		}
		return notify.Publish(r.Context(), tx, p.ProjectID, "deletion_request", id.String(), "local_pending", 0)
	})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "state": "local_pending", "collector_request_id": collectorRequestID})
}

// GetPolicy returns the effective project policy.
func (s *Service) GetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleViewer)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	var settings []byte
	if err := s.DB.Pool.QueryRow(r.Context(), `select settings from projects where id=$1`, p.ProjectID).Scan(&settings); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, PolicyFromSettings(settings))
}

// SetPolicy replaces the project policy for future evidence and run metadata.
func (s *Service) SetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	var policy Policy
	if err := httpapi.DecodeJSON(r, &policy, 8<<10); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if err := policy.validate(); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	encoded, _ := json.Marshal(policy)
	err = s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `update projects set settings=jsonb_set(settings,'{retention}',$2::jsonb,true) where id=$1`, p.ProjectID, encoded)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return httpapi.E(http.StatusNotFound, "not_found", "unknown project")
		}
		rawTTL := time.Duration(policy.RawEvidenceDays) * 24 * time.Hour
		metadataTTL := time.Duration(policy.MetadataDays) * 24 * time.Hour
		if _, err := tx.Exec(r.Context(), `update recordings set retention_until=least(coalesce(retention_until,created_at+$2::interval),created_at+$2::interval) where project_id=$1 and state in ('open','sealed')`, p.ProjectID, rawTTL); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `update capture_runs set retention_until=least(coalesce(retention_until,created_at+$2::interval),created_at+$2::interval) where project_id=$1 and state='active'`, p.ProjectID, metadataTTL); err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'retention.policy_update','project',$3,$4)`, p.ProjectID, p.Subject, p.ProjectID.String(), encoded)
		return err
	})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, policy)
}

// RequestDelete creates an idempotent, full CaptureRun deletion. Immutable raw
// evidence makes narrower erasure unverifiable, so recording/session requests
// are deliberately escalated and the effective CaptureRun is returned.
func (s *Service) RequestDelete(ctx context.Context, p auth.Principal, entityType, entityID string, req DeleteRequest) (*Status, error) {
	if p.Kind != auth.KindUser || !p.HasRole(auth.RoleAdmin) {
		return nil, httpapi.E(http.StatusForbidden, "forbidden", "admin role required")
	}
	if entityType != "recording" && entityType != "capture_run" && entityType != "session" {
		return nil, httpapi.E(http.StatusInternalServerError, "internal", "unsupported deletion entity")
	}
	if entityID == "" || len(entityID) > 256 || strings.ContainsAny(entityID, "\x00\r\n") {
		return nil, httpapi.E(http.StatusBadRequest, "malformed_request", "entity id is invalid")
	}
	if req.Confirmation != entityID {
		return nil, httpapi.E(http.StatusBadRequest, "confirmation_mismatch", "confirmation must exactly match the requested entity id")
	}
	if len(req.Reason) > maxDeleteReasonBytes || strings.ContainsAny(req.Reason, "\x00\r\n") {
		return nil, httpapi.E(http.StatusBadRequest, "malformed_request", "deletion reason is invalid")
	}
	var requestID uuid.UUID
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var repeated uuid.UUID
		err := tx.QueryRow(ctx, `select id from deletion_requests where project_id=$1 and requested_entity_type=$2 and requested_entity_id=$3 and mode='full' order by requested_at limit 1`, p.ProjectID, entityType, entityID).Scan(&repeated)
		if err == nil {
			requestID = repeated
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		runID, collectorID, recordingID, err := resolveTarget(ctx, tx, p.ProjectID, entityType, entityID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, runID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `select id from capture_runs where id=$1 and project_id=$2 for update`, runID, p.ProjectID).Scan(new(string)); err != nil {
			return err
		}
		var existing uuid.UUID
		err = tx.QueryRow(ctx, `select id from deletion_requests where project_id=$1 and capture_run_id=$2 and mode='full'`, p.ProjectID, runID).Scan(&existing)
		if err == nil {
			requestID = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		requestID = uuid.New()
		var collectorRequestID *uuid.UUID
		if collectorID != nil && recordingID != nil {
			id := uuid.New()
			payload, _ := json.Marshal(map[string]any{"recording_id": *recordingID, "capture_run_id": runID, "reason": "platform_delete"})
			if _, err := tx.Exec(ctx, `insert into collector_requests(id,collector_id,project_id,type,payload,status,created_by,expires_at) values($1,$2,$3,'delete_local',$4,'pending',$5,null)`, id, *collectorID, p.ProjectID, payload, p.Subject); err != nil {
				return err
			}
			collectorRequestID = &id
		}
		if _, err := tx.Exec(ctx, `update capture_runs set state='deleting' where id=$1 and project_id=$2 and state<>'deleted'`, runID, p.ProjectID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update recordings set state='deleting',deletion_started_at=coalesce(deletion_started_at,now()),updated_at=now() where capture_run_id=$1 and project_id=$2 and state<>'deleted'`, runID, p.ProjectID); err != nil {
			return err
		}
		// Revoke queued/recoverable control work for this run before the
		// collector can replay a backfill, seal, or sensitive-upload command.
		// The newly-created whole-run delete command is explicitly excluded.
		canceled, err := tx.Exec(ctx, `update collector_requests cr set status='expired',finished_at=now(),result=jsonb_build_object('reason','superseded by capture run deletion') where cr.project_id=$1 and cr.status in ('pending','delivered','acked') and ($3::uuid is null or cr.id<>$3) and (cr.payload->>'capture_run_id'=$2 or exists(select 1 from recordings r where r.project_id=$1 and r.capture_run_id=$2 and r.id=cr.payload->>'recording_id'))`, p.ProjectID, runID, collectorRequestID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update processing_jobs set status='done',finished_at=coalesce(finished_at,now()),lease_owner=null,lease_until=null where capture_run_id=$1 and project_id=$2 and status='pending'`, runID, p.ProjectID); err != nil {
			return err
		}
		var reason *string
		if req.Reason != "" {
			reason = &req.Reason
		}
		if _, err := tx.Exec(ctx, `insert into deletion_requests(id,project_id,requested_entity_type,requested_entity_id,capture_run_id,mode,recording_id,collector_id,collector_request_id,requested_by,reason) values($1,$2,$3,$4,$5,'full',$6,$7,$8,$9,$10)`, requestID, p.ProjectID, entityType, entityID, runID, recordingID, collectorID, collectorRequestID, p.Subject, reason); err != nil {
			return err
		}
		detail := map[string]any{"capture_run_id": runID, "effective_scope": "capture_run", "deletion_request_id": requestID, "canceled_collector_requests": canceled.RowsAffected()}
		if collectorRequestID != nil {
			detail["collector_request_id"] = *collectorRequestID
		}
		if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'retention.delete_request',$3,$4,$5)`, p.ProjectID, p.Subject, entityType, entityID, detail); err != nil {
			return err
		}
		return notify.Publish(ctx, tx, p.ProjectID, "deletion_request", requestID.String(), "pending", 0)
	})
	if err != nil {
		return nil, err
	}
	return scanStatus(s.DB.Pool.QueryRow(ctx, `select `+statusColumns+` from deletion_requests where id=$1 and project_id=$2`, requestID, p.ProjectID))
}

func resolveTarget(ctx context.Context, tx pgx.Tx, project uuid.UUID, entityType, entityID string) (string, *uuid.UUID, *string, error) {
	var runID string
	var collectorID *uuid.UUID
	switch entityType {
	case "capture_run":
		err := tx.QueryRow(ctx, `select id,collector_id from capture_runs where id=$1 and project_id=$2`, entityID, project).Scan(&runID, &collectorID)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, nil, httpapi.E(http.StatusNotFound, "not_found", "unknown capture run")
		}
		if err != nil {
			return "", nil, nil, err
		}
	case "recording":
		err := tx.QueryRow(ctx, `select c.id,c.collector_id from recordings r join capture_runs c on c.id=r.capture_run_id where r.id=$1 and r.project_id=$2`, entityID, project).Scan(&runID, &collectorID)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, nil, httpapi.E(http.StatusNotFound, "not_found", "unknown recording")
		}
		if err != nil {
			return "", nil, nil, err
		}
	case "session":
		err := tx.QueryRow(ctx, `select s.capture_run_id,c.collector_id from sessions s join capture_runs c on c.id=s.capture_run_id where s.id=$1 and s.project_id=$2`, entityID, project).Scan(&runID, &collectorID)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, nil, httpapi.E(http.StatusNotFound, "not_found", "unknown session")
		}
		if err != nil {
			return "", nil, nil, err
		}
	}
	var recordingID string
	// A whole-run delete is always addressed through segment zero. The
	// collector erases the complete run, and its crash-recovery path derives
	// the run ID from the canonical #0000 suffix after the directory has moved
	// into quarantine.
	err := tx.QueryRow(ctx, `select id from recordings where capture_run_id=$1 and project_id=$2 order by segment_no asc limit 1`, runID, project).Scan(&recordingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return runID, collectorID, nil, nil
	}
	if err != nil {
		return "", nil, nil, err
	}
	return runID, collectorID, &recordingID, nil
}

// Sweep advances due TTL work and deletion state machines. Every stage is
// idempotent and may be called concurrently by multiple API replicas.
func (s *Service) Sweep(ctx context.Context) error {
	if err := s.enqueueDueMetadata(ctx); err != nil {
		return err
	}
	if err := s.enqueueDueEvidence(ctx); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		worked, err := s.prepareOne(ctx)
		if err != nil {
			return err
		}
		if !worked {
			break
		}
	}
	for i := 0; i < objectDeleteBatch; i++ {
		worked, err := s.deleteOneObject(ctx)
		if err != nil {
			return err
		}
		if !worked {
			break
		}
	}
	for i := 0; i < 20; i++ {
		worked, err := s.finalizeOne(ctx)
		if err != nil {
			return err
		}
		if !worked {
			break
		}
	}
	if err := s.reconcileLocal(ctx); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		worked, err := s.deleteOneStaleBlobUpload(ctx)
		if err != nil {
			return err
		}
		if !worked {
			break
		}
	}
	return nil
}

func (s *Service) enqueueDueMetadata(ctx context.Context) error {
	rows, err := s.DB.Pool.Query(ctx, `select id,project_id from capture_runs where state='active' and ended_at is not null and retention_until<=now() order by retention_until limit 20`)
	if err != nil {
		return err
	}
	type due struct {
		run     string
		project uuid.UUID
	}
	items := make([]due, 0)
	for rows.Next() {
		var item due
		if err := rows.Scan(&item.run, &item.project); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		p := auth.Principal{Kind: auth.KindUser, ProjectID: item.project, Subject: "platform-retention", Role: auth.RoleAdmin}
		_, err := s.RequestDelete(ctx, p, "capture_run", item.run, DeleteRequest{Confirmation: item.run, Reason: "metadata_ttl"})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) enqueueDueEvidence(ctx context.Context) error {
	rows, err := s.DB.Pool.Query(ctx, `select r.id,r.project_id,r.capture_run_id from recordings r join capture_runs c on c.id=r.capture_run_id where r.state='sealed' and r.retention_until<=now() and c.state='active' order by r.retention_until limit 20`)
	if err != nil {
		return err
	}
	type due struct {
		recording, run string
		project        uuid.UUID
	}
	items := make([]due, 0)
	for rows.Next() {
		var item due
		if err := rows.Scan(&item.recording, &item.project, &item.run); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
			var state string
			if err := tx.QueryRow(ctx, `select state from recordings where id=$1 and project_id=$2 for update`, item.recording, item.project).Scan(&state); err != nil {
				return err
			}
			if state != "sealed" {
				return nil
			}
			id := uuid.New()
			tag, err := tx.Exec(ctx, `insert into deletion_requests(id,project_id,requested_entity_type,requested_entity_id,capture_run_id,mode,recording_id,requested_by,reason) values($1,$2,'retention',$3,$4,'evidence',$3,'platform-retention','raw_evidence_ttl') on conflict do nothing`, id, item.project, item.recording, item.run)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			if _, err := tx.Exec(ctx, `update recordings set state='expiring',deletion_started_at=coalesce(deletion_started_at,now()),updated_at=now() where id=$1`, item.recording); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `update processing_jobs set status='done',finished_at=coalesce(finished_at,now()),lease_owner=null,lease_until=null where project_id=$1 and capture_run_id=$2 and status='pending'`, item.project, item.run); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,'platform-retention','retention.evidence_expire_request','recording',$2,jsonb_build_object('deletion_request_id',$3::text))`, item.project, item.recording, id); err != nil {
				return err
			}
			return notify.Publish(ctx, tx, item.project, "deletion_request", id.String(), "pending", 0)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

type deletionWork struct {
	id        uuid.UUID
	project   uuid.UUID
	run       string
	mode      string
	recording *string
}

func (s *Service) prepareOne(ctx context.Context) (bool, error) {
	var work deletionWork
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `select id,project_id,capture_run_id,mode,recording_id from deletion_requests where state in ('pending','waiting_workers') and next_attempt_at<=now() order by requested_at for update skip locked limit 1`).Scan(&work.id, &work.project, &work.run, &work.mode, &work.recording)
		if err != nil {
			return err
		}
		if work.mode == "evidence" && work.recording == nil {
			return fmt.Errorf("evidence deletion %s has no recording_id", work.id)
		}
		// Serialize with blob uploads and batch reference registration. Without
		// this lock a concurrent run could make a blob shared after the candidate
		// query but before the object is fenced as deleting.
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, work.project.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update processing_jobs set status='done',finished_at=coalesce(finished_at,now()),lease_owner=null,lease_until=null where capture_run_id=$1 and project_id=$2 and status='pending'`, work.run, work.project); err != nil {
			return err
		}
		var leased int
		if err := tx.QueryRow(ctx, `select count(*) from processing_jobs where capture_run_id=$1 and project_id=$2 and status='leased'`, work.run, work.project).Scan(&leased); err != nil {
			return err
		}
		if leased > 0 {
			_, err := tx.Exec(ctx, `update deletion_requests set state='waiting_workers',attempts=attempts+1,next_attempt_at=now()+interval '5 seconds',last_error='waiting for leased processing jobs' where id=$1`, work.id)
			return err
		}
		keys, blobs, err := s.deletionKeys(ctx, tx, work)
		if err != nil {
			return err
		}
		for _, object := range keys {
			if _, err := tx.Exec(ctx, `insert into deletion_objects(deletion_request_id,object_key,kind) values($1,$2,$3) on conflict do nothing`, work.id, object.key, object.kind); err != nil {
				return err
			}
		}
		for _, blob := range blobs {
			if _, err := tx.Exec(ctx, `update blobs set state='deleting' where project_id=$1 and sha256=$2 and state in ('active','uploading')`, work.project, blob.sha); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `insert into deletion_objects(deletion_request_id,object_key,kind) values($1,$2,'blob') on conflict do nothing`, work.id, blob.key); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `update deletion_requests set state='deleting_objects',attempts=attempts+1,next_attempt_at=now(),last_error=null where id=$1`, work.id)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil && work.id != uuid.Nil && ctx.Err() == nil {
		message := truncate(err.Error(), 4000)
		_, updateErr := s.DB.Pool.Exec(ctx, `update deletion_requests set state='waiting_workers',attempts=attempts+1,next_attempt_at=now()+interval '15 seconds',last_error=$2 where id=$1 and state in ('pending','waiting_workers')`, work.id, message)
		if updateErr != nil {
			return true, updateErr
		}
		return true, nil
	}
	return err == nil, err
}

type objectDelete struct{ key, kind string }
type blobDelete struct {
	sha []byte
	key string
}

func (s *Service) deletionKeys(ctx context.Context, tx pgx.Tx, work deletionWork) ([]objectDelete, []blobDelete, error) {
	lister, ok := s.Obj.(objstore.PrefixLister)
	if !ok {
		return nil, nil, fmt.Errorf("object store does not support deletion prefix discovery")
	}
	keyKinds := make(map[string]string)
	var rows pgx.Rows
	var err error
	if work.mode == "full" {
		rows, err = tx.Query(ctx, `select b.object_key,'batch' from batches b join recordings r on r.id=b.recording_id where r.capture_run_id=$1 and r.project_id=$2 union all select e.object_key,'export' from exports e where e.capture_run_id=$1 and e.project_id=$2 and e.object_key is not null`, work.run, work.project)
	} else {
		rows, err = tx.Query(ctx, `select b.object_key,'batch' from batches b where b.recording_id=$1 union all select e.object_key,'export' from exports e where e.capture_run_id=$2 and e.project_id=$3 and e.object_key is not null`, *work.recording, work.run, work.project)
	}
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var item objectDelete
		if err := rows.Scan(&item.key, &item.kind); err != nil {
			rows.Close()
			return nil, nil, err
		}
		keyKinds[item.key] = item.kind
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	var tenant uuid.UUID
	if err := tx.QueryRow(ctx, `select tenant_id from projects where id=$1`, work.project).Scan(&tenant); err != nil {
		return nil, nil, err
	}
	recordingIDs := make([]string, 0)
	if work.mode == "full" {
		rows, err = tx.Query(ctx, `select id from recordings where project_id=$1 and capture_run_id=$2 order by segment_no`, work.project, work.run)
	} else {
		rows, err = tx.Query(ctx, `select id from recordings where project_id=$1 and id=$2`, work.project, *work.recording)
	}
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var recordingID string
		if err := rows.Scan(&recordingID); err != nil {
			rows.Close()
			return nil, nil, err
		}
		recordingIDs = append(recordingIDs, recordingID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, recordingID := range recordingIDs {
		prefix := objstore.RecordingPrefix(tenant.String(), work.project.String(), recordingID) + "batches/"
		listed, err := lister.ListPrefix(ctx, prefix, 10_001)
		if err != nil {
			return nil, nil, fmt.Errorf("list recording objects %s: %w", recordingID, err)
		}
		if len(listed) >= 10_001 {
			return nil, nil, fmt.Errorf("recording %s exceeds the bounded 10000-object deletion inventory", recordingID)
		}
		for _, object := range listed {
			reader, err := s.Obj.Get(ctx, object.Key)
			if err != nil {
				return nil, nil, fmt.Errorf("read batch header %s: %w", object.Key, err)
			}
			header, readErr := protocol.ReadBatchHeader(reader)
			closeErr := reader.Close()
			if readErr != nil {
				return nil, nil, fmt.Errorf("validate batch header %s: %w", object.Key, readErr)
			}
			if closeErr != nil {
				return nil, nil, fmt.Errorf("close batch object %s: %w", object.Key, closeErr)
			}
			if header.RecordingID != recordingID {
				return nil, nil, fmt.Errorf("batch object %s belongs to recording %s, expected %s", object.Key, header.RecordingID, recordingID)
			}
			for _, reference := range header.Blobs {
				digest, err := hex.DecodeString(reference.SHA256)
				if err != nil || len(digest) != 32 {
					return nil, nil, fmt.Errorf("batch object %s has an invalid blob digest", object.Key)
				}
				if _, err := tx.Exec(ctx, `insert into recording_blob_refs(recording_id,project_id,sha256) values($1,$2,$3) on conflict do nothing`, recordingID, work.project, digest); err != nil {
					return nil, nil, err
				}
			}
			keyKinds[object.Key] = "batch"
		}
	}
	var exportIDs []uuid.UUID
	rows, err = tx.Query(ctx, `select id from exports where project_id=$1 and capture_run_id=$2`, work.project, work.run)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var exportID uuid.UUID
		if err := rows.Scan(&exportID); err != nil {
			rows.Close()
			return nil, nil, err
		}
		exportIDs = append(exportIDs, exportID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, exportID := range exportIDs {
		prefix := fmt.Sprintf("%s/%s/exports/%s/", tenant, work.project, exportID)
		listed, err := lister.ListPrefix(ctx, prefix, 101)
		if err != nil {
			return nil, nil, fmt.Errorf("list export objects %s: %w", exportID, err)
		}
		if len(listed) >= 101 {
			return nil, nil, fmt.Errorf("export %s exceeds the bounded 100-object deletion inventory", exportID)
		}
		for _, object := range listed {
			keyKinds[object.Key] = "export"
		}
	}
	keys := make([]objectDelete, 0, len(keyKinds))
	for key, kind := range keyKinds {
		keys = append(keys, objectDelete{key: key, kind: kind})
	}
	if work.mode == "full" {
		rows, err = tx.Query(ctx, `select distinct rr.sha256,coalesce(b.object_key,'') from recording_blob_refs rr join recordings r on r.id=rr.recording_id left join blobs b on b.project_id=rr.project_id and b.sha256=rr.sha256 where rr.project_id=$1 and r.capture_run_id=$2 and not exists(select 1 from recording_blob_refs outside join recordings ro on ro.id=outside.recording_id where outside.project_id=rr.project_id and outside.sha256=rr.sha256 and ro.capture_run_id<>$2)`, work.project, work.run)
	} else {
		rows, err = tx.Query(ctx, `select distinct rr.sha256,coalesce(b.object_key,'') from recording_blob_refs rr left join blobs b on b.project_id=rr.project_id and b.sha256=rr.sha256 where rr.project_id=$1 and rr.recording_id=$2 and not exists(select 1 from recording_blob_refs outside where outside.project_id=rr.project_id and outside.sha256=rr.sha256 and outside.recording_id<>$2)`, work.project, *work.recording)
	}
	if err != nil {
		return nil, nil, err
	}
	blobs := make([]blobDelete, 0)
	for rows.Next() {
		var item blobDelete
		if err := rows.Scan(&item.sha, &item.key); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if item.key == "" {
			if len(item.sha) != 32 {
				rows.Close()
				return nil, nil, fmt.Errorf("recording blob reference has an invalid digest length")
			}
			item.key = objstore.BlobKey(tenant.String(), work.project.String(), hex.EncodeToString(item.sha))
		}
		blobs = append(blobs, item)
	}
	rows.Close()
	return keys, blobs, rows.Err()
}

func (s *Service) deleteOneObject(ctx context.Context) (bool, error) {
	var requestID uuid.UUID
	var key string
	err := s.DB.Pool.QueryRow(ctx, `with candidate as (
		select o.deletion_request_id,o.object_key from deletion_objects o join deletion_requests d on d.id=o.deletion_request_id
		where d.state='deleting_objects' and o.next_attempt_at<=now() and (o.state='pending' or o.state='deleting' and o.lease_until<now())
		order by d.requested_at,o.object_key for update of o skip locked limit 1
	) update deletion_objects o set state='deleting',attempts=o.attempts+1,lease_until=now()+interval '2 minutes',last_error=null from candidate c
	where o.deletion_request_id=c.deletion_request_id and o.object_key=c.object_key returning o.deletion_request_id,o.object_key`).Scan(&requestID, &key)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := s.Obj.Delete(ctx, key); err != nil {
		message := truncate(err.Error(), 4000)
		_, updateErr := s.DB.Pool.Exec(ctx, `update deletion_objects set state='pending',lease_until=null,next_attempt_at=now()+interval '5 seconds',last_error=$3 where deletion_request_id=$1 and object_key=$2`, requestID, key, message)
		if updateErr != nil {
			return true, updateErr
		}
		return true, nil
	}
	_, err = s.DB.Pool.Exec(ctx, `update deletion_objects set state='done',lease_until=null,deleted_at=now(),last_error=null where deletion_request_id=$1 and object_key=$2`, requestID, key)
	return true, err
}

func (s *Service) finalizeOne(ctx context.Context) (bool, error) {
	var work deletionWork
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `select d.id,d.project_id,d.capture_run_id,d.mode,d.recording_id from deletion_requests d where d.state='deleting_objects' and d.next_attempt_at<=now() and not exists(select 1 from deletion_objects o where o.deletion_request_id=d.id and o.state<>'done') order by d.requested_at for update skip locked limit 1`).Scan(&work.id, &work.project, &work.run, &work.mode, &work.recording)
		if err != nil {
			return err
		}
		if work.mode == "evidence" && work.recording == nil {
			return fmt.Errorf("evidence deletion %s has no recording_id", work.id)
		}
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, work.run); err != nil {
			return err
		}
		if work.mode == "full" {
			return s.finalizeFull(ctx, tx, work)
		}
		return s.finalizeEvidence(ctx, tx, work)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil && work.id != uuid.Nil && ctx.Err() == nil {
		message := truncate(err.Error(), 4000)
		_, updateErr := s.DB.Pool.Exec(ctx, `update deletion_requests set attempts=attempts+1,next_attempt_at=now()+interval '15 seconds',last_error=$2 where id=$1 and state='deleting_objects'`, work.id, message)
		if updateErr != nil {
			return true, updateErr
		}
		return true, nil
	}
	return err == nil, err
}

func (s *Service) finalizeFull(ctx context.Context, tx pgx.Tx, work deletionWork) error {
	var leased int
	if err := tx.QueryRow(ctx, `select count(*) from processing_jobs where project_id=$1 and capture_run_id=$2 and status='leased'`, work.project, work.run).Scan(&leased); err != nil {
		return err
	}
	if leased > 0 {
		_, err := tx.Exec(ctx, `update deletion_requests set state='waiting_workers',next_attempt_at=now()+interval '5 seconds',last_error='processing job leased after object staging' where id=$1`, work.id)
		return err
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`delete from processing_jobs where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from assembly_state where capture_run_id=$1`, []any{work.run}},
		{`delete from findings where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from relations where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from sessions where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from capture_tasks where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from model_inferences where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from model_attempts where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from recording_events where recording_id in (select id from recordings where project_id=$1 and capture_run_id=$2)`, []any{work.project, work.run}},
		{`delete from batches where recording_id in (select id from recordings where project_id=$1 and capture_run_id=$2)`, []any{work.project, work.run}},
		{`delete from exports where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from recording_blob_refs where project_id=$1 and recording_id in (select id from recordings where project_id=$1 and capture_run_id=$2)`, []any{work.project, work.run}},
		{`delete from blobs b using deletion_objects o where o.deletion_request_id=$2 and o.kind='blob' and o.state='done' and b.project_id=$1 and b.state='deleting' and b.object_key=o.object_key`, []any{work.project, work.id}},
		{`update blobs b set ref_count=(select count(*)::int from recording_blob_refs rr where rr.project_id=b.project_id and rr.sha256=b.sha256) where b.project_id=$1`, []any{work.project}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `update recordings set state='deleted',manifest=null,manifest_sha256=null,coverage=null,coverage_revision=0,integrity_alerts='[]'::jsonb,missing_blobs='[]'::jsonb,durable_seq=sequence_base,parsed_seq=sequence_base,final_seq=null,sealed_at=null,retention_until=null,deleted_at=now(),deleted_by=(select requested_by from deletion_requests where id=$3),updated_at=now() where project_id=$1 and capture_run_id=$2`, work.project, work.run, work.id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `update capture_runs set state='deleted',collector_id=null,command=null,cwd=null,agent_kind=null,agent_version=null,started_at=null,ended_at=null,exit_code=null,metadata='{}'::jsonb,relation_revision=0,analysis_revision=0,transport_proof=null,transport_proof_revision=0,benchmark_result=null,retention_until=null,deleted_at=now(),deleted_by=(select requested_by from deletion_requests where id=$3) where project_id=$1 and id=$2`, work.project, work.run, work.id); err != nil {
		return err
	}
	var collectorRequestID *uuid.UUID
	if err := tx.QueryRow(ctx, `select collector_request_id from deletion_requests where id=$1`, work.id).Scan(&collectorRequestID); err != nil {
		return err
	}
	state := "done"
	if collectorRequestID != nil {
		state = "local_pending"
	}
	if _, err := tx.Exec(ctx, `update deletion_requests set state=$2,remote_deleted_at=now(),completed_at=case when $2='done' then now() else null end,last_error=null where id=$1`, work.id, state); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) select project_id,'platform-retention','retention.remote_delete','capture_run',capture_run_id,jsonb_build_object('deletion_request_id',id::text,'local_state',$2::text) from deletion_requests where id=$1`, work.id, state); err != nil {
		return err
	}
	return notify.Publish(ctx, tx, work.project, "deletion_request", work.id.String(), state, 0)
}

func (s *Service) finalizeEvidence(ctx context.Context, tx pgx.Tx, work deletionWork) error {
	recording := *work.recording
	var leased int
	if err := tx.QueryRow(ctx, `select count(*) from processing_jobs where project_id=$1 and capture_run_id=$2 and status='leased'`, work.project, work.run).Scan(&leased); err != nil {
		return err
	}
	if leased > 0 {
		_, err := tx.Exec(ctx, `update deletion_requests set state='waiting_workers',next_attempt_at=now()+interval '5 seconds',last_error='processing job leased after object staging' where id=$1`, work.id)
		return err
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`delete from processing_jobs where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from assembly_state where capture_run_id=$1`, []any{work.run}},
		{`delete from findings where project_id=$1 and recording_id=$2`, []any{work.project, recording}},
		{`delete from recording_events where recording_id=$1`, []any{recording}},
		{`delete from batches where recording_id=$1`, []any{recording}},
		{`delete from exports where project_id=$1 and capture_run_id=$2`, []any{work.project, work.run}},
		{`delete from recording_blob_refs where project_id=$1 and recording_id=$2`, []any{work.project, recording}},
		{`delete from blobs b using deletion_objects o where o.deletion_request_id=$2 and o.kind='blob' and o.state='done' and b.project_id=$1 and b.state='deleting' and b.object_key=o.object_key`, []any{work.project, work.id}},
		{`update blobs b set ref_count=(select count(*)::int from recording_blob_refs rr where rr.project_id=b.project_id and rr.sha256=b.sha256) where b.project_id=$1`, []any{work.project}},
		{`update model_attempts set request_headers=null,response_headers=null,request_body=null,request_body_ref=null,response_body=null,response_body_ref=null,response_text=null,normalized=null,projection=null,input_hash=null,updated_at=now() where project_id=$1 and recording_id=$2`, []any{work.project, recording}},
		{`update model_inferences set request=null,response=null,normalized=null,resolved_input_ref=null,input_hash=null,updated_at=now() where project_id=$1 and recording_id=$2`, []any{work.project, recording}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	// A concurrent full-run deletion may already have advanced this recording
	// to deleting/deleted. Evidence expiry may still finish its idempotent
	// cleanup, but must never move the lifecycle state backwards to expired.
	if _, err := tx.Exec(ctx, `update recordings set state='expired',coverage=coalesce(coverage,'{}'::jsonb)||jsonb_build_object('claim','coverage_unknown','raw_expired',true),missing_blobs='[]'::jsonb,deleted_at=now(),deleted_by='platform-retention',updated_at=now() where id=$1 and project_id=$2 and state='expiring'`, recording, work.project); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `update deletion_requests set state='done',remote_deleted_at=now(),completed_at=now(),last_error=null where id=$1`, work.id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,'platform-retention','retention.evidence_expire','recording',$2,jsonb_build_object('deletion_request_id',$3::text))`, work.project, recording, work.id); err != nil {
		return err
	}
	return notify.Publish(ctx, tx, work.project, "deletion_request", work.id.String(), "done", 0)
}

func (s *Service) reconcileLocal(ctx context.Context) error {
	return s.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `select d.id,d.project_id,d.capture_run_id,c.status from deletion_requests d join collector_requests c on c.id=d.collector_request_id where d.state='local_pending' and c.status in ('done','rejected','expired') for update of d skip locked`)
		if err != nil {
			return err
		}
		type item struct {
			id      uuid.UUID
			project uuid.UUID
			run     string
			status  string
		}
		items := make([]item, 0)
		for rows.Next() {
			var entry item
			if err := rows.Scan(&entry.id, &entry.project, &entry.run, &entry.status); err != nil {
				rows.Close()
				return err
			}
			items = append(items, entry)
		}
		rows.Close()
		for _, entry := range items {
			state, action := "local_failed", "retention.local_delete_failed"
			if entry.status == "done" {
				state, action = "done", "retention.local_delete_done"
			}
			if _, err := tx.Exec(ctx, `update deletion_requests set state=$2,completed_at=now(),last_error=case when $2='local_failed' then $3 else null end where id=$1`, entry.id, state, "collector request "+entry.status); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,'platform-retention',$2,'capture_run',$3,jsonb_build_object('deletion_request_id',$4::text,'collector_status',$5::text))`, entry.project, action, entry.run, entry.id, entry.status); err != nil {
				return err
			}
			if err := notify.Publish(ctx, tx, entry.project, "deletion_request", entry.id.String(), state, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

// deleteOneStaleBlobUpload removes an object whose durable upload intent was
// never activated. PutBlob holds the same project advisory lock across object
// publication, so once this lock is acquired an eligible row cannot still have
// an in-flight writer. References always win over garbage collection.
func (s *Service) deleteOneStaleBlobUpload(ctx context.Context) (bool, error) {
	var project uuid.UUID
	var digest []byte
	var key string
	err := s.DB.Pool.QueryRow(ctx, `select b.project_id,b.sha256,b.object_key from blobs b where b.state='uploading' and b.first_seen_at<=now()-$1::interval and not exists(select 1 from recording_blob_refs r where r.project_id=b.project_id and r.sha256=b.sha256) order by b.first_seen_at limit 1`, staleBlobUploadGrace.String()).Scan(&project, &digest, &key)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = s.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, project.String()); err != nil {
			return err
		}
		var eligible bool
		if err := tx.QueryRow(ctx, `select exists(select 1 from blobs b where b.project_id=$1 and b.sha256=$2 and b.state='uploading' and b.first_seen_at<=now()-$3::interval and not exists(select 1 from recording_blob_refs r where r.project_id=b.project_id and r.sha256=b.sha256))`, project, digest, staleBlobUploadGrace.String()).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return nil
		}
		if err := s.Obj.Delete(ctx, key); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `delete from blobs b where b.project_id=$1 and b.sha256=$2 and b.state='uploading' and not exists(select 1 from recording_blob_refs r where r.project_id=b.project_id and r.sha256=b.sha256)`, project, digest)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		_, err = tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,'platform-retention','retention.orphan_blob_delete','blob',$2,jsonb_build_object('object_key',$3::text,'reason','stale_uncommitted_upload'))`, project, hex.EncodeToString(digest), key)
		return err
	})
	return true, err
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
