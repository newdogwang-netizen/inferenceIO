// Package exporter implements bounded, auditable platform exports.
package exporter

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/store"
)

const (
	// Version binds queued jobs and exported rows to this implementation.
	Version                     = "export-v1"
	formatNormalizedJSONL       = "normalized-jsonl"
	mediaTypeJSONL              = "application/x-ndjson"
	maxExportBytes        int64 = 2 << 30
	maxExportRows               = 1_000_000
	maxExportLineBytes          = 64 << 20
	exportTTL                   = 7 * 24 * time.Hour
)

// Service serves export control-plane requests and worker execution.
type Service struct {
	DB  *store.DB
	Obj objstore.Store
}

type createRequest struct {
	CaptureRunID string `json:"capture_run_id"`
	Format       string `json:"format"`
}

type exportInput struct {
	ExportID string `json:"export_id"`
	Format   string `json:"format"`
}

type metadata struct {
	ID           uuid.UUID  `json:"id"`
	CaptureRunID string     `json:"capture_run_id"`
	Format       string     `json:"format"`
	State        string     `json:"state"`
	Filename     string     `json:"filename"`
	MediaType    string     `json:"media_type"`
	SHA256       *string    `json:"sha256,omitempty"`
	ByteLength   *int64     `json:"byte_length,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	LastError    *string    `json:"last_error,omitempty"`
}

func validateFormat(format string) error {
	if format != formatNormalizedJSONL {
		return httpapi.E(http.StatusBadRequest, "unsupported_export_format", "format must be normalized-jsonl")
	}
	return nil
}

// Create validates and enqueues an immutable export.
func (s *Service) Create(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	var req createRequest
	if err := httpapi.DecodeJSON(r, &req, 1<<16); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if req.CaptureRunID == "" || len(req.CaptureRunID) > 256 || strings.ContainsAny(req.CaptureRunID, "\x00\r\n") {
		httpapi.WriteError(w, r, httpapi.E(http.StatusBadRequest, "malformed_request", "capture_run_id is invalid"))
		return
	}
	if err := validateFormat(req.Format); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id := uuid.New()
	filename := "iorec-export-" + id.String() + ".normalized.jsonl"
	expires := time.Now().UTC().Add(exportTTL)
	err = s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		var finalized, active bool
		if err := tx.QueryRow(r.Context(), `select ended_at is not null,state='active' from capture_runs where id=$1 and project_id=$2`, req.CaptureRunID, p.ProjectID).Scan(&finalized, &active); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(http.StatusNotFound, "not_found", "unknown capture run")
			}
			return err
		}
		if !active {
			return httpapi.E(http.StatusConflict, "capture_run_deleting", "capture run is deleting or deleted")
		}
		if !finalized {
			return httpapi.E(http.StatusConflict, "capture_run_open", "capture run must be finalized before export")
		}
		var activeJobs int
		if err := tx.QueryRow(r.Context(), `select count(*) from processing_jobs where capture_run_id=$1 and project_id=$2 and type in ('decode','assemble','normalize','resolve','coverage') and status in ('pending','leased')`, req.CaptureRunID, p.ProjectID).Scan(&activeJobs); err != nil {
			return err
		}
		if activeJobs != 0 {
			return httpapi.E(http.StatusConflict, "capture_run_processing", "capture run processing must finish before export")
		}
		var incompleteRecordings, failedJobs int
		if err := tx.QueryRow(r.Context(), `select count(*) from recordings where capture_run_id=$1 and project_id=$2 and (state<>'sealed' or parsed_seq<>durable_seq)`, req.CaptureRunID, p.ProjectID).Scan(&incompleteRecordings); err != nil {
			return err
		}
		if err := tx.QueryRow(r.Context(), `select count(*) from processing_jobs where capture_run_id=$1 and project_id=$2 and type in ('decode','assemble','normalize','resolve','coverage') and status in ('failed','dead')`, req.CaptureRunID, p.ProjectID).Scan(&failedJobs); err != nil {
			return err
		}
		if incompleteRecordings != 0 || failedJobs != 0 {
			return httpapi.E(http.StatusConflict, "capture_run_incomplete", "capture run must be fully parsed without failed required jobs before export")
		}
		if _, err := tx.Exec(r.Context(), `insert into exports(id,project_id,capture_run_id,format,filename,media_type,expires_at,created_by) values($1,$2,$3,$4,$5,$6,$7,$8)`, id, p.ProjectID, req.CaptureRunID, req.Format, filename, mediaTypeJSONL, expires, p.Subject); err != nil {
			return err
		}
		if _, err := jobs.Enqueue(r.Context(), tx, jobs.Spec{ProjectID: p.ProjectID, Type: jobs.TypeExport, CaptureRunID: req.CaptureRunID, InputRef: exportInput{ExportID: id.String(), Format: req.Format}, ProcessorVersion: Version, Priority: 0}); err != nil {
			return err
		}
		_, err := tx.Exec(r.Context(), `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'export.create','export',$3,$4)`, p.ProjectID, p.Subject, id.String(), map[string]any{"capture_run_id": req.CaptureRunID, "format": req.Format})
		return err
	})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "state": "pending", "expires_at": expires})
}

func scanMetadata(row pgx.Row) (metadata, error) {
	var m metadata
	var digest []byte
	if err := row.Scan(&m.ID, &m.CaptureRunID, &m.Format, &m.State, &m.Filename, &m.MediaType, &digest, &m.ByteLength, &m.ExpiresAt, &m.CreatedAt, &m.CompletedAt, &m.LastError); err != nil {
		return m, err
	}
	if len(digest) != 0 {
		value := hex.EncodeToString(digest)
		m.SHA256 = &value
	}
	return m, nil
}

// Get returns metadata without exposing object-store keys.
func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpapi.WriteError(w, r, httpapi.E(http.StatusBadRequest, "malformed_request", "bad export id"))
		return
	}
	m, err := scanMetadata(s.DB.Pool.QueryRow(r.Context(), `select id,capture_run_id,format,state,filename,media_type,sha256,byte_length,expires_at,created_at,completed_at,last_error from exports where id=$1 and project_id=$2`, id, p.ProjectID))
	if errors.Is(err, pgx.ErrNoRows) {
		httpapi.WriteError(w, r, httpapi.E(http.StatusNotFound, "not_found", "unknown export"))
		return
	}
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, m)
}

// List returns bounded project-scoped export metadata.
func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	rows, err := s.DB.Pool.Query(r.Context(), `select id,capture_run_id,format,state,filename,media_type,sha256,byte_length,expires_at,created_at,completed_at,last_error from exports where project_id=$1 order by created_at desc limit 500`, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]metadata, 0)
	for rows.Next() {
		m, err := scanMetadata(rows)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Download streams one ready, unexpired export through the authenticated API.
func (s *Service) Download(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleAdmin)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpapi.WriteError(w, r, httpapi.E(http.StatusBadRequest, "malformed_request", "bad export id"))
		return
	}
	var key, filename, mediaType string
	var size int64
	var digest []byte
	err = s.DB.Pool.QueryRow(r.Context(), `select e.object_key,e.filename,e.media_type,e.byte_length,e.sha256 from exports e join capture_runs c on c.id=e.capture_run_id and c.project_id=e.project_id where e.id=$1 and e.project_id=$2 and e.state='ready' and e.expires_at>now() and c.state='active'`, id, p.ProjectID).Scan(&key, &filename, &mediaType, &size, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		httpapi.WriteError(w, r, httpapi.E(http.StatusNotFound, "not_found", "ready unexpired export not found"))
		return
	}
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	rc, err := s.Obj.Get(r.Context(), key)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	defer rc.Close()
	if _, err := s.DB.Pool.Exec(r.Context(), `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'export.download','export',$3,'{}'::jsonb)`, p.ProjectID, p.Subject, id.String()); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest))
	_, _ = io.CopyN(w, rc, size)
}

// SweepExpired removes expired export objects and retains only audit metadata.
func (s *Service) SweepExpired(ctx context.Context) error {
	rows, err := s.DB.Pool.Query(ctx, `select id,project_id,object_key from exports where state='ready' and expires_at<=now() order by expires_at limit 100`)
	if err != nil {
		return err
	}
	type expired struct {
		id      uuid.UUID
		project uuid.UUID
		key     string
	}
	var items []expired
	for rows.Next() {
		var item expired
		if err := rows.Scan(&item.id, &item.project, &item.key); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range items {
		if err := s.Obj.Delete(ctx, item.key); err != nil {
			return err
		}
		if err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `update exports set state='expired',object_key=null where id=$1 and project_id=$2 and state='ready' and expires_at<=now()`, item.id, item.project)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			_, err = tx.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,'platform-export-expiry','export.expire','export',$2,'{}'::jsonb)`, item.project, item.id.String())
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

type boundedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("export exceeds %d-byte limit", maxExportBytes)
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

// Run executes a leased normalized-jsonl export job idempotently.
func (s *Service) Run(ctx context.Context, j *jobs.Job) (retErr error) {
	if j.CaptureRunID == nil || j.ProcessorVersion != Version {
		return fmt.Errorf("export job identity or processor version is invalid")
	}
	var input exportInput
	if err := json.Unmarshal(j.InputRef, &input); err != nil {
		return fmt.Errorf("parse export input: %w", err)
	}
	exportID, err := uuid.Parse(input.ExportID)
	if err != nil || validateFormat(input.Format) != nil {
		return fmt.Errorf("export input is invalid")
	}
	var tenantID uuid.UUID
	var runID, format, state, filename, mediaType, key string
	var readyDigest []byte
	var readyBytes *int64
	err = s.DB.Pool.QueryRow(ctx, `select p.tenant_id,e.capture_run_id,e.format,e.state,e.filename,e.media_type,coalesce(e.object_key,''),e.sha256,e.byte_length from exports e join projects p on p.id=e.project_id where e.id=$1 and e.project_id=$2`, exportID, j.ProjectID).Scan(&tenantID, &runID, &format, &state, &filename, &mediaType, &key, &readyDigest, &readyBytes)
	if err != nil {
		return err
	}
	if runID != *j.CaptureRunID || format != input.Format {
		return fmt.Errorf("export job does not match its row")
	}
	if state == "ready" && key != "" && readyBytes != nil && len(readyDigest) == sha256.Size {
		if err := verifyPublishedObject(ctx, s.Obj, key, *readyBytes, readyDigest); err != nil {
			return fmt.Errorf("ready export object verification: %w", err)
		}
		return nil
	}
	if state != "pending" && state != "running" && state != "failed" {
		return fmt.Errorf("export row is not runnable from state %q", state)
	}
	if _, err := s.DB.Pool.Exec(ctx, `update exports set state='running',last_error=null where id=$1 and project_id=$2`, exportID, j.ProjectID); err != nil {
		return err
	}
	defer func() {
		if retErr == nil {
			return
		}
		message := retErr.Error()
		if len(message) > 2000 {
			message = message[:2000]
		}
		failedState := "pending"
		if j.Attempts >= jobs.MaxAttempts {
			failedState = "failed"
		}
		_, _ = s.DB.Pool.Exec(context.Background(), `update exports set state=$3,last_error=$4 where id=$1 and project_id=$2 and state='running'`, exportID, j.ProjectID, failedState, message)
	}()

	tmp, err := os.CreateTemp("", ".iorec-export-*.jsonl")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	bw := bufio.NewWriterSize(&boundedWriter{w: tmp, remaining: maxExportBytes}, 256<<10)
	rows, err := s.DB.Pool.Query(ctx, `select jsonb_build_object(
		'schema_version','iorec-platform-normalized-jsonl-v1',
		'capture_run_id',i.capture_run_id,
		'inference_id',i.id,
		'native_id',i.native_id,
		'status',i.status,
		'attempt_count',i.attempt_count,
		'first_attempt_at',i.first_attempt_at,
		'model',i.model,
		'api_mode',i.api_mode,
		'task_id',i.task_id,
		'session_id',i.session_id,
		'turn_id',i.turn_id,
		'server_state',i.server_state,
		'request',i.request,
		'response',i.response,
		'normalized',i.normalized,
		'usage',i.usage,
		'evidence_refs',i.evidence_refs,
		'attempts',coalesce((select jsonb_agg(jsonb_build_object('id',a.id,'native_id',a.native_id,'terminal_state',a.terminal_state,'status_code',a.status_code,'provider_host',a.provider_host,'started_at',a.started_at,'ended_at',a.ended_at,'sse_event_count',a.sse_event_count) order by a.started_at,a.id) from model_attempts a where a.inference_id=i.id and a.project_id=i.project_id),'[]'::jsonb),
		'relations',coalesce((select jsonb_agg(jsonb_build_object('type',r.type,'from_id',r.from_id,'to_id',r.to_id,'status',r.status,'confidence',r.confidence,'evidence',r.evidence) order by r.id) from relations r where r.project_id=i.project_id and r.capture_run_id=i.capture_run_id and (r.from_id=i.id or r.to_id=i.id) and r.superseded_by is null),'[]'::jsonb),
		'coverage',coalesce((select jsonb_agg(jsonb_build_object('recording_id',rec.id,'segment_no',rec.segment_no,'claim',rec.coverage->>'claim','coverage',rec.coverage) order by rec.segment_no) from recordings rec where rec.capture_run_id=i.capture_run_id and rec.project_id=i.project_id),'[]'::jsonb)
	)::text from model_inferences i where i.capture_run_id=$1 and i.project_id=$2 order by i.first_attempt_at nulls last,i.id`, runID, j.ProjectID)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		count++
		if count > maxExportRows {
			rows.Close()
			return fmt.Errorf("export exceeds %d-row limit", maxExportRows)
		}
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			return err
		}
		if len(line) > maxExportLineBytes {
			rows.Close()
			return fmt.Errorf("export row exceeds %d-byte limit", maxExportLineBytes)
		}
		if _, err := bw.WriteString(line + "\n"); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	info, err := tmp.Stat()
	if err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, tmp); err != nil {
		return err
	}
	digest := h.Sum(nil)
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	key = objstore.ExportKey(tenantID.String(), j.ProjectID.String(), exportID.String(), filename)
	if err := s.Obj.Put(ctx, key, tmp, info.Size(), mediaType); err != nil {
		return err
	}
	if err := verifyPublishedObject(ctx, s.Obj, key, info.Size(), digest); err != nil {
		return fmt.Errorf("export object verification failed: %w", err)
	}
	tag, err := s.DB.Pool.Exec(ctx, `update exports set state='ready',object_key=$3,sha256=$4,byte_length=$5,completed_at=now(),last_error=null where id=$1 and project_id=$2 and state='running'`, exportID, j.ProjectID, key, digest, info.Size())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("export row changed before publication completed")
	}
	return nil
}

func verifyPublishedObject(ctx context.Context, objectStore objstore.Store, key string, expectedBytes int64, expectedDigest []byte) error {
	if expectedBytes < 0 || expectedBytes > maxExportBytes || len(expectedDigest) != sha256.Size {
		return fmt.Errorf("invalid expected export identity")
	}
	stored, err := objectStore.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("open stored object: %w", err)
	}
	storedHash := sha256.New()
	storedBytes, copyErr := io.Copy(storedHash, io.LimitReader(stored, maxExportBytes+1))
	closeErr := stored.Close()
	if copyErr != nil || closeErr != nil || storedBytes != expectedBytes || !strings.EqualFold(hex.EncodeToString(storedHash.Sum(nil)), hex.EncodeToString(expectedDigest)) {
		return fmt.Errorf("identity mismatch: bytes=%d copy_err=%v close_err=%v", storedBytes, copyErr, closeErr)
	}
	return nil
}
