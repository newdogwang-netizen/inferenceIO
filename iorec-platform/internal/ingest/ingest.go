// Package ingest implements the data-plane receive path (platform/04):
// batch validation, immutable object write, transactional registration,
// durable_seq advancement, idempotency and conflicts, blob upload, seal.
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/notify"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/retention"
	"github.com/heidihealth/iorec-platform/internal/store"
)

// ProcessorVersions used when enqueuing first-stage jobs.
const DecoderVersion = "decoder-v1"

// Service wires the receive path.
type Service struct {
	DB                     *store.DB
	Obj                    objstore.Store
	MaxProjectStorageBytes int64
}

// DefaultMaxProjectStorageBytes is the logical raw-evidence quota used when
// no deployment-specific value is configured.
const DefaultMaxProjectStorageBytes int64 = 100 << 30

func lockProjectStorage(ctx context.Context, tx pgx.Tx, project uuid.UUID) error {
	_, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, project.String())
	return err
}

func (s *Service) checkProjectStorage(ctx context.Context, tx pgx.Tx, project uuid.UUID, additional int64) error {
	limit := s.MaxProjectStorageBytes
	if limit <= 0 {
		limit = DefaultMaxProjectStorageBytes
	}
	if additional < 0 || additional > limit {
		return httpapi.E(http.StatusTooManyRequests, "storage_quota_exceeded", "project evidence storage quota exceeded")
	}
	// Serialize quota reservations across API replicas without adding a
	// mutable counter that could diverge from the authoritative catalog.
	if err := lockProjectStorage(ctx, tx, project); err != nil {
		return err
	}
	var used int64
	if err := tx.QueryRow(ctx, `select
		coalesce((select sum(size) from blobs where project_id=$1),0) +
		coalesce((select sum(b.byte_length) from batches b join recordings r on r.id=b.recording_id where r.project_id=$1),0)`, project).Scan(&used); err != nil {
		return err
	}
	if used > limit-additional {
		return httpapi.E(http.StatusTooManyRequests, "storage_quota_exceeded", "project evidence storage quota exceeded")
	}
	return nil
}

func (s *Service) verifyBatchObject(ctx context.Context, key string, offered protocol.BatchHeader) error {
	reader, err := s.Obj.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("read published batch object: %w", err)
	}
	defer reader.Close()
	stored, _, _, err := protocol.ReadBatchBody(reader)
	if err != nil {
		return fmt.Errorf("verify published batch object: %w", err)
	}
	if stored.BatchID != offered.BatchID || stored.RecordingID != offered.RecordingID ||
		stored.FirstSeq != offered.FirstSeq || stored.LastSeq != offered.LastSeq || stored.SHA256 != offered.SHA256 {
		return httpapi.E(http.StatusConflict, "object_conflict", "immutable batch object contains different evidence")
	}
	return nil
}

func (s *Service) verifyBlobObject(ctx context.Context, key, shaHex string, size int64) error {
	reader, err := s.Obj.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("read published blob object: %w", err)
	}
	defer reader.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(reader, MaxBlobBytes+1))
	if err != nil {
		return err
	}
	if written != size || hex.EncodeToString(hash.Sum(nil)) != shaHex {
		return httpapi.E(http.StatusConflict, "object_conflict", "immutable blob object contains different evidence")
	}
	return nil
}

// CreateRecordingRequest is the body of POST /recordings.
type CreateRecordingRequest struct {
	RecordingID   string       `json:"recording_id"`
	CaptureRunID  string       `json:"capture_run_id"`
	SegmentNo     int          `json:"segment_no"`
	SequenceBase  int64        `json:"sequence_base"`
	SchemaVersion int          `json:"schema_version"`
	Run           *RunMetadata `json:"run,omitempty"`
}

// RunMetadata describes the capture run (RUN-002).
type RunMetadata struct {
	Command      string          `json:"command,omitempty"`
	Cwd          string          `json:"cwd,omitempty"`
	AgentKind    string          `json:"agent_kind,omitempty"`
	AgentVersion string          `json:"agent_version,omitempty"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

// CreateRecording upserts the capture run and recording. Idempotent.
func (s *Service) CreateRecording(ctx context.Context, p auth.Principal, req CreateRecordingRequest) error {
	if req.RecordingID == "" || req.CaptureRunID == "" {
		return httpapi.E(400, "malformed_request", "recording_id and capture_run_id required")
	}
	if len(req.RecordingID) > 240 || strings.ContainsAny(req.RecordingID, "\x00\r\n") ||
		len(req.CaptureRunID) > 256 || strings.ContainsAny(req.CaptureRunID, "\x00\r\n") ||
		req.SegmentNo < 0 || req.SegmentNo >= 10000 || req.SequenceBase < 0 ||
		(req.SegmentNo == 0 && req.SequenceBase != 0) {
		return httpapi.E(400, "malformed_request", "recording identity is invalid")
	}
	if req.SchemaVersion == 0 {
		req.SchemaVersion = 1
	}
	if req.SchemaVersion != 1 {
		return httpapi.E(http.StatusUnsupportedMediaType, "unsupported_schema", "schema_version not supported")
	}
	if req.Run != nil && (len(req.Run.Command) > 64<<10 || len(req.Run.Cwd) > 16<<10 ||
		len(req.Run.AgentKind) > 1<<10 || len(req.Run.AgentVersion) > 1<<10 ||
		strings.ContainsRune(req.Run.Command, '\x00') || strings.ContainsRune(req.Run.Cwd, '\x00') ||
		strings.ContainsRune(req.Run.AgentKind, '\x00') || strings.ContainsRune(req.Run.AgentVersion, '\x00')) {
		return httpapi.E(400, "malformed_request", "run metadata is invalid")
	}
	if req.Run != nil && len(req.Run.Metadata) > 0 {
		var metadata map[string]any
		if len(req.Run.Metadata) > 256<<10 || json.Unmarshal(req.Run.Metadata, &metadata) != nil || metadata == nil {
			return httpapi.E(400, "malformed_request", "run metadata must be a bounded JSON object")
		}
	}
	return s.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, req.CaptureRunID); err != nil {
			return err
		}
		var projectSettings []byte
		if err := tx.QueryRow(ctx, `select settings from projects where id=$1`, p.ProjectID).Scan(&projectSettings); err != nil {
			return err
		}
		policy := retention.PolicyFromSettings(projectSettings)
		rawRetention := time.Duration(policy.RawEvidenceDays) * 24 * time.Hour
		metadataRetention := time.Duration(policy.MetadataDays) * 24 * time.Hour
		var collector *uuid.UUID
		if p.CollectorID != uuid.Nil {
			c := p.CollectorID
			collector = &c
		}
		md := json.RawMessage(`{}`)
		var cmd, cwd, kind, ver *string
		var started *time.Time
		if req.Run != nil {
			if len(req.Run.Metadata) > 0 {
				md = req.Run.Metadata
			}
			cmd, cwd, kind, ver = nz(req.Run.Command), nz(req.Run.Cwd), nz(req.Run.AgentKind), nz(req.Run.AgentVersion)
			started = req.Run.StartedAt
		}
		// capture run: insert or verify project ownership
		var existingProject uuid.UUID
		var existingCollector *uuid.UUID
		var existingEndedAt *time.Time
		var existingRunState string
		claimCollector := false
		err := tx.QueryRow(ctx, `select project_id, collector_id, ended_at, state from capture_runs where id=$1 for update`, req.CaptureRunID).Scan(&existingProject, &existingCollector, &existingEndedAt, &existingRunState)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx, `insert into capture_runs(id, project_id, collector_id, command, cwd, agent_kind, agent_version, started_at, metadata, retention_until) values($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+$10::interval)`,
				req.CaptureRunID, p.ProjectID, collector, cmd, cwd, kind, ver, started, md, metadataRetention); err != nil {
				return err
			}
			existingRunState = "active"
		case err != nil:
			return err
		case existingProject != p.ProjectID:
			return httpapi.E(http.StatusForbidden, "forbidden", "capture_run belongs to another project")
		case existingRunState != "active":
			return httpapi.E(http.StatusGone, "capture_run_deleted", "capture run is deleting or deleted")
		case existingCollector != nil && p.CollectorID != uuid.Nil && *existingCollector != p.CollectorID:
			return httpapi.E(http.StatusConflict, "capture_run_conflict", "capture_run belongs to another collector")
		default:
			claimCollector = existingCollector == nil && p.CollectorID != uuid.Nil
			if req.Run != nil {
				if _, err := tx.Exec(ctx, `update capture_runs set command=coalesce($2,command), cwd=coalesce($3,cwd), agent_kind=coalesce($4,agent_kind), agent_version=coalesce($5,agent_version), started_at=coalesce($6,started_at), metadata = metadata || $7 where id=$1`,
					req.CaptureRunID, cmd, cwd, kind, ver, started, md); err != nil {
					return err
				}
			}
		}
		var recProject uuid.UUID
		var existingRun string
		var existingSegment, existingSchema int
		var existingSequenceBase int64
		err = tx.QueryRow(ctx, `select project_id, capture_run_id, segment_no, sequence_base, schema_version from recordings where id=$1`, req.RecordingID).Scan(&recProject, &existingRun, &existingSegment, &existingSequenceBase, &existingSchema)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if existingEndedAt != nil {
				return httpapi.E(http.StatusConflict, "capture_run_finalized", "capture run no longer accepts new recording segments")
			}
			if req.SegmentNo > 0 {
				var predecessorState string
				var predecessorFinal *int64
				err := tx.QueryRow(ctx, `select state, final_seq from recordings where project_id=$1 and capture_run_id=$2 and segment_no=$3 for update`, p.ProjectID, req.CaptureRunID, req.SegmentNo-1).Scan(&predecessorState, &predecessorFinal)
				if errors.Is(err, pgx.ErrNoRows) {
					return httpapi.E(http.StatusConflict, "segment_predecessor_missing", "previous recording segment does not exist")
				}
				if err != nil {
					return err
				}
				if predecessorState != "sealed" || predecessorFinal == nil || *predecessorFinal != req.SequenceBase {
					return httpapi.E(http.StatusConflict, "segment_sequence_conflict", "recording segment does not continue a sealed predecessor")
				}
			}
			if _, err := tx.Exec(ctx, `insert into recordings(id, project_id, capture_run_id, segment_no, sequence_base, schema_version, durable_seq, parsed_seq, retention_until) values($1,$2,$3,$4,$5,$6,$5,$5,now()+$7::interval)`,
				req.RecordingID, p.ProjectID, req.CaptureRunID, req.SegmentNo, req.SequenceBase, req.SchemaVersion, rawRetention); err != nil {
				if store.IsUniqueViolation(err) {
					return httpapi.E(http.StatusConflict, "recording_conflict", "capture_run/segment_no already used by another recording")
				}
				return err
			}
			if err := notify.Publish(ctx, tx, p.ProjectID, "recording", req.RecordingID, "created", 0); err != nil {
				return err
			}
		case err != nil:
			return err
		case recProject != p.ProjectID:
			return httpapi.E(http.StatusForbidden, "forbidden", "recording belongs to another project")
		case existingRun != req.CaptureRunID || existingSegment != req.SegmentNo || existingSequenceBase != req.SequenceBase || existingSchema != req.SchemaVersion:
			return httpapi.E(http.StatusConflict, "recording_conflict", "recording identity is already bound to different metadata")
		}
		if claimCollector {
			var incompatible bool
			if err := tx.QueryRow(ctx, `select exists(select 1 from recordings where capture_run_id=$1 and origin <> 'upload')`, req.CaptureRunID).Scan(&incompatible); err != nil {
				return err
			}
			if incompatible {
				return httpapi.E(http.StatusConflict, "capture_run_conflict", "an imported capture run cannot be claimed by a collector")
			}
			if _, err := tx.Exec(ctx, `update capture_runs set collector_id=$2 where id=$1 and collector_id is null`, req.CaptureRunID, p.CollectorID); err != nil {
				return err
			}
		}
		return nil
	})
}

func nz(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// BatchResult is the ACK body.
type BatchResult struct {
	RecordingID  string   `json:"recording_id"`
	DurableSeq   int64    `json:"durable_seq"`
	State        string   `json:"state"`
	MissingBlobs []string `json:"missing_blobs"`
	Duplicate    bool     `json:"duplicate,omitempty"`
}

// UploadBatch implements POST /recordings/{id}/batches.
func (s *Service) UploadBatch(ctx context.Context, p auth.Principal, recordingID string, body io.Reader) (*BatchResult, error) {
	hdr, compressed, raw, err := protocol.ReadBatchBody(body)
	if err != nil {
		return nil, mapDecodeErr(err)
	}
	if hdr.RecordingID != recordingID {
		return nil, httpapi.E(400, "malformed_batch", "header recording_id does not match path")
	}
	if err := protocol.ValidateHeaderRange(hdr); err != nil {
		return nil, mapDecodeErr(err)
	}
	if _, err := protocol.ParseEvents(hdr, raw); err != nil {
		return nil, mapDecodeErr(err)
	}
	// Ownership & state check (cheap read before object write).
	var project, tenant uuid.UUID
	var state string
	var sequenceBase int64
	var sealedFinal *int64
	err = s.DB.Pool.QueryRow(ctx, `select r.project_id, p.tenant_id, r.state, r.sequence_base, r.final_seq from recordings r join projects p on p.id=r.project_id where r.id=$1`, recordingID).Scan(&project, &tenant, &state, &sequenceBase, &sealedFinal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, httpapi.E(404, "recording_not_found", "unknown recording; create it first")
	}
	if err != nil {
		return nil, err
	}
	if project != p.ProjectID {
		return nil, httpapi.E(403, "forbidden", "recording belongs to another project")
	}
	if state != "open" && state != "sealed" {
		return nil, httpapi.E(409, "recording_sealed", "recording no longer accepts batches (state "+state+")")
	}
	if hdr.FirstSeq <= sequenceBase {
		return nil, httpapi.E(400, "malformed_batch", "batch sequence range does not follow the recording sequence base")
	}
	if state == "sealed" && (sealedFinal == nil || hdr.LastSeq > *sealedFinal) {
		return nil, httpapi.E(409, "final_seq_conflict", "batch sequence range exceeds the sealed final sequence")
	}
	// Idempotent object write. Key is determined by the seq range.
	key := objstore.RecordingPrefix(tenant.String(), project.String(), recordingID) + protocol.BatchObjectKey(hdr.FirstSeq, hdr.LastSeq)
	var wire bytes.Buffer
	if err := protocol.WriteBatchBody(&wire, hdr, compressed); err != nil {
		return nil, err
	}
	shaBytes, _ := hex.DecodeString(hdr.SHA256)
	res := &BatchResult{RecordingID: recordingID, MissingBlobs: []string{}}
	err = s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var durable, lockedSequenceBase int64
		var lockedFinal *int64
		if err := tx.QueryRow(ctx, `select durable_seq, state, sequence_base, final_seq from recordings where id=$1 for update`, recordingID).Scan(&durable, &res.State, &lockedSequenceBase, &lockedFinal); err != nil {
			return err
		}
		if hdr.FirstSeq <= lockedSequenceBase {
			return httpapi.E(400, "malformed_batch", "batch sequence range does not follow the recording sequence base")
		}
		if res.State != "open" && res.State != "sealed" {
			return httpapi.E(http.StatusConflict, "recording_deleting", "recording no longer accepts batches (state "+res.State+")")
		}
		if res.State == "sealed" && (lockedFinal == nil || hdr.LastSeq > *lockedFinal) {
			return httpapi.E(409, "final_seq_conflict", "batch sequence range exceeds the sealed final sequence")
		}
		// Blob-reference registration and deletion candidate selection share this
		// project lock. It closes the race where a duplicate/legacy batch repairs
		// a reference while retention is deciding that the blob is unshared.
		if err := lockProjectStorage(ctx, tx, project); err != nil {
			return err
		}
		// existing batch?
		var existingSHA []byte
		err := tx.QueryRow(ctx, `select sha256 from batches where recording_id=$1 and batch_id=$2`, recordingID, hdr.BatchID).Scan(&existingSHA)
		if err == nil {
			if bytes.Equal(existingSHA, shaBytes) {
				if err := s.Obj.Put(ctx, key, bytes.NewReader(wire.Bytes()), int64(wire.Len()), protocol.ContentTypeBatch); err != nil {
					return fmt.Errorf("object put: %w", err)
				}
				if err := s.verifyBatchObject(ctx, key, hdr); err != nil {
					return err
				}
				if err := registerBlobRefs(ctx, tx, recordingID, project, hdr.Blobs); err != nil {
					return err
				}
				res.DurableSeq = durable
				res.Duplicate = true
				return nil
			}
			alert := map[string]any{"kind": "batch_conflict", "batch_id": hdr.BatchID, "existing_sha256": hex.EncodeToString(existingSHA), "offered_sha256": hdr.SHA256, "at": time.Now().UTC()}
			ab, _ := json.Marshal(alert)
			_, _ = tx.Exec(ctx, `update recordings set integrity_alerts = integrity_alerts || $2::jsonb where id=$1`, recordingID, ab)
			// commit the alert even though we return a conflict
			return &conflictErr{httpapi.E(409, "batch_conflict", "batch_id exists with different sha256").WithDetails(map[string]any{"existing_sha256": hex.EncodeToString(existingSHA)})}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var overlap bool
		if err := tx.QueryRow(ctx, `select exists(select 1 from batches where recording_id=$1 and first_seq <= $3 and last_seq >= $2)`, recordingID, hdr.FirstSeq, hdr.LastSeq).Scan(&overlap); err != nil {
			return err
		}
		if overlap {
			return httpapi.E(409, "batch_overlap", "seq range overlaps an existing batch with different boundaries")
		}
		if err := s.checkProjectStorage(ctx, tx, project, hdr.ByteLength); err != nil {
			return err
		}
		if err := s.Obj.Put(ctx, key, bytes.NewReader(wire.Bytes()), int64(wire.Len()), protocol.ContentTypeBatch); err != nil {
			return fmt.Errorf("object put: %w", err)
		}
		if err := s.verifyBatchObject(ctx, key, hdr); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into batches(recording_id, batch_id, first_seq, last_seq, event_count, byte_length, sha256, object_key) values($1,$2,$3,$4,$5,$6,$7,$8)`,
			recordingID, hdr.BatchID, hdr.FirstSeq, hdr.LastSeq, hdr.EventCount, hdr.ByteLength, shaBytes, key); err != nil {
			return err
		}
		if err := registerBlobRefs(ctx, tx, recordingID, project, hdr.Blobs); err != nil {
			return err
		}
		// advance durable_seq over contiguous batches
		for i := 0; i < 100000; i++ {
			var last int64
			err := tx.QueryRow(ctx, `select last_seq from batches where recording_id=$1 and first_seq=$2`, recordingID, durable+1).Scan(&last)
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				return err
			}
			durable = last
		}
		if _, err := tx.Exec(ctx, `update recordings set durable_seq=$2, updated_at=now() where id=$1`, recordingID, durable); err != nil {
			return err
		}
		res.DurableSeq = durable
		// missing blobs
		for _, b := range hdr.Blobs {
			bs, err := hex.DecodeString(b.SHA256)
			if err != nil {
				continue
			}
			var exists bool
			if err := tx.QueryRow(ctx, `select exists(select 1 from blobs where project_id=$1 and sha256=$2 and state='active')`, project, bs).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				res.MissingBlobs = append(res.MissingBlobs, b.SHA256)
			}
		}
		if len(res.MissingBlobs) > 0 {
			mb, _ := json.Marshal(res.MissingBlobs)
			if _, err := tx.Exec(ctx, `update recordings set missing_blobs = (select coalesce(jsonb_agg(distinct x), '[]'::jsonb) from jsonb_array_elements(missing_blobs || $2::jsonb) x) where id=$1`, recordingID, mb); err != nil {
				return err
			}
		}
		var runID string
		if err := tx.QueryRow(ctx, `select capture_run_id from recordings where id=$1`, recordingID).Scan(&runID); err != nil {
			return err
		}
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: project, Type: jobs.TypeDecode, RecordingID: recordingID, CaptureRunID: runID,
			InputRef: map[string]any{"batch_id": hdr.BatchID, "first_seq": hdr.FirstSeq, "last_seq": hdr.LastSeq}, ProcessorVersion: DecoderVersion, Priority: 10}); err != nil {
			return err
		}
		return notify.Publish(ctx, tx, project, "recording", recordingID, "durable_seq", durable)
	})
	if err != nil {
		var ce *conflictErr
		if errors.As(err, &ce) {
			// persist alert in its own tx, then return conflict
			_ = s.DB.Tx(ctx, func(tx pgx.Tx) error {
				alert := map[string]any{"kind": "batch_conflict", "batch_id": hdr.BatchID, "offered_sha256": hdr.SHA256, "at": time.Now().UTC()}
				ab, _ := json.Marshal(alert)
				_, err := tx.Exec(ctx, `update recordings set integrity_alerts = integrity_alerts || $2::jsonb where id=$1`, recordingID, ab)
				return err
			})
			return nil, ce.APIError
		}
		return nil, err
	}
	return res, nil
}

func registerBlobRefs(ctx context.Context, tx pgx.Tx, recordingID string, project uuid.UUID, refs []protocol.BlobRef) error {
	seen := make(map[string]struct{}, len(refs))
	for _, blob := range refs {
		if _, duplicate := seen[blob.SHA256]; duplicate {
			continue
		}
		seen[blob.SHA256] = struct{}{}
		digest, err := hex.DecodeString(blob.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return httpapi.E(http.StatusBadRequest, "malformed_batch", "blob reference sha256 is invalid")
		}
		if _, err := tx.Exec(ctx, `insert into recording_blob_refs(recording_id,project_id,sha256) values($1,$2,$3) on conflict do nothing`, recordingID, project, digest); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update blobs b set ref_count=(select count(*)::int from recording_blob_refs rr where rr.project_id=b.project_id and rr.sha256=b.sha256) where b.project_id=$1 and b.sha256=$2`, project, digest); err != nil {
			return err
		}
	}
	return nil
}

type conflictErr struct{ *httpapi.APIError }

func (c *conflictErr) Error() string { return c.APIError.Error() }

func mapDecodeErr(err error) error {
	var de *protocol.DecodeError
	if errors.As(err, &de) {
		status := 400
		switch de.Code {
		case "payload_too_large":
			status = 413
		case "hash_mismatch", "seq_discontinuity", "malformed_batch":
			status = 400
		}
		return httpapi.E(status, de.Code, de.Msg)
	}
	return err
}

// MaxBlobBytes bounds blob uploads (platform/03 §7).
const MaxBlobBytes = 256 << 20

// PutBlob stores a content-addressed blob after verifying its digest.
func (s *Service) PutBlob(ctx context.Context, p auth.Principal, shaHex string, mediaType string, body io.Reader) (created bool, err error) {
	if len(shaHex) != 64 {
		return false, httpapi.E(400, "malformed_request", "sha256 must be 64 hex chars")
	}
	shaBytes, err := hex.DecodeString(shaHex)
	if err != nil {
		return false, httpapi.E(400, "malformed_request", "sha256 not hex")
	}
	tmp, err := os.CreateTemp("", "iorec-blob-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, MaxBlobBytes+1))
	if err != nil {
		return false, err
	}
	if n > MaxBlobBytes {
		return false, httpapi.E(413, "payload_too_large", "blob exceeds limit")
	}
	if hex.EncodeToString(h.Sum(nil)) != shaHex {
		return false, httpapi.E(422, "hash_mismatch", "blob content does not match sha256")
	}
	key := objstore.BlobKey(p.TenantID.String(), p.ProjectID.String(), shaHex)
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	// Keep the project advisory lock on one database session across both the
	// intent commit and immutable object publication. The committed "uploading"
	// row makes a crash recoverable; the session lock prevents retention from
	// racing the object write after that intent becomes visible.
	conn, err := s.DB.Pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(hashtextextended($1,0))`, p.ProjectID.String()); err != nil {
		return false, err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, `select pg_advisory_unlock(hashtextextended($1,0))`, p.ProjectID.String())
	}()

	needsActivation := false
	err = func() error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		var existingSize int64
		var existingState string
		err = tx.QueryRow(ctx, `select size,state from blobs where project_id=$1 and sha256=$2 for update`, p.ProjectID, shaBytes).Scan(&existingSize, &existingState)
		switch {
		case err == nil:
			if existingState == "deleting" {
				return httpapi.E(http.StatusServiceUnavailable, "blob_deleting", "blob is being erased; retry upload")
			}
			if existingState != "active" && existingState != "uploading" {
				return fmt.Errorf("blob has unsupported state %q", existingState)
			}
			if existingSize != n {
				return httpapi.E(http.StatusConflict, "blob_conflict", "blob digest has a conflicting catalogued size")
			}
			needsActivation = existingState == "uploading"
			created = needsActivation
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		default:
			if err := s.checkProjectStorage(ctx, tx, p.ProjectID, n); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `insert into blobs(project_id,sha256,size,media_type,object_key,ref_count,state) values($1,$2,$3,$4,$5,(select count(*)::int from recording_blob_refs where project_id=$1 and sha256=$2),'uploading')`, p.ProjectID, shaBytes, n, mediaType, key); err != nil {
				return err
			}
			needsActivation = true
			created = true
		}
		return tx.Commit(ctx)
	}()
	if err != nil {
		return false, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if err := s.Obj.Put(ctx, key, tmp, n, mediaType); err != nil {
		return false, err
	}
	if err := s.verifyBlobObject(ctx, key, shaHex, n); err != nil {
		return false, err
	}
	if !needsActivation {
		return false, nil
	}
	err = func() error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		var state string
		if err := tx.QueryRow(ctx, `select state from blobs where project_id=$1 and sha256=$2 for update`, p.ProjectID, shaBytes).Scan(&state); err != nil {
			return err
		}
		if state == "deleting" {
			return httpapi.E(http.StatusServiceUnavailable, "blob_deleting", "blob is being erased; retry upload")
		}
		if state != "uploading" {
			return fmt.Errorf("blob upload intent has unsupported state %q", state)
		}
		if _, err := tx.Exec(ctx, `update blobs set state='active' where project_id=$1 and sha256=$2 and state='uploading'`, p.ProjectID, shaBytes); err != nil {
			return err
		}
		// resolve missing_blobs on recordings and enqueue re-normalization
		rows, err := tx.Query(ctx, `select id, capture_run_id from recordings where project_id=$1 and missing_blobs ? $2`, p.ProjectID, shaHex)
		if err != nil {
			return err
		}
		type rr struct{ id, run string }
		var recs []rr
		for rows.Next() {
			var r rr
			if err := rows.Scan(&r.id, &r.run); err != nil {
				rows.Close()
				return err
			}
			recs = append(recs, r)
		}
		rows.Close()
		for _, r := range recs {
			if _, err := tx.Exec(ctx, `update recordings set missing_blobs = missing_blobs - $2 where id=$1`, r.id, shaHex); err != nil {
				return err
			}
			if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: p.ProjectID, Type: jobs.TypeNormalize, RecordingID: r.id, CaptureRunID: r.run,
				InputRef: map[string]any{"blob_arrived": shaHex}, ProcessorVersion: "normalizer-v1", Priority: 5}); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}()
	return created, err
}

// BlobExists checks the catalog.
func (s *Service) BlobExists(ctx context.Context, p auth.Principal, shaHex string) (bool, int64, error) {
	shaBytes, err := hex.DecodeString(shaHex)
	if err != nil {
		return false, 0, httpapi.E(400, "malformed_request", "sha256 not hex")
	}
	var size int64
	err = s.DB.Pool.QueryRow(ctx, `select size from blobs where project_id=$1 and sha256=$2 and state='active'`, p.ProjectID, shaBytes).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, nil
	}
	return err == nil, size, err
}

// OpenBlob returns the blob content for a project.
func (s *Service) OpenBlob(ctx context.Context, project, tenant uuid.UUID, shaHex string) (io.ReadCloser, string, error) {
	shaBytes, err := hex.DecodeString(shaHex)
	if err != nil {
		return nil, "", httpapi.E(400, "malformed_request", "sha256 not hex")
	}
	var key, mt string
	err = s.DB.Pool.QueryRow(ctx, `select object_key, coalesce(media_type,'application/octet-stream') from blobs where project_id=$1 and sha256=$2 and state='active'`, project, shaBytes).Scan(&key, &mt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", httpapi.E(404, "blob_not_found", "unknown blob")
	}
	if err != nil {
		return nil, "", err
	}
	rc, err := s.Obj.Get(ctx, key)
	if errors.Is(err, objstore.ErrNotFound) {
		return nil, "", httpapi.E(404, "blob_object_missing", "blob catalogued but object missing")
	}
	return rc, mt, err
}

// SealRequest is POST /recordings/{id}:seal.
type SealRequest struct {
	FinalSeq       int64           `json:"final_seq"`
	Manifest       json.RawMessage `json:"manifest,omitempty"`
	ManifestSHA256 string          `json:"manifest_sha256,omitempty"`
	Incomplete     bool            `json:"incomplete,omitempty"`
	RunFinal       *bool           `json:"run_final,omitempty"`
}

// Seal marks the recording sealed and stores the collector manifest.
func (s *Service) Seal(ctx context.Context, p auth.Principal, recordingID string, req SealRequest) error {
	if req.FinalSeq <= 0 {
		return httpapi.E(400, "malformed_request", "final_seq must be positive")
	}
	var manifestSHA []byte
	if len(req.Manifest) > 0 {
		digest := sha256.Sum256(req.Manifest)
		manifestSHA = digest[:]
		if req.ManifestSHA256 != "" {
			if len(req.ManifestSHA256) != 64 || req.ManifestSHA256 != strings.ToLower(req.ManifestSHA256) {
				return httpapi.E(400, "malformed_request", "manifest_sha256 must be 64 lowercase hex characters")
			}
			offered, err := hex.DecodeString(req.ManifestSHA256)
			if err != nil || !bytes.Equal(offered, manifestSHA) {
				return httpapi.E(422, "hash_mismatch", "manifest content does not match manifest_sha256")
			}
		}
	} else if req.ManifestSHA256 != "" {
		return httpapi.E(400, "malformed_request", "manifest_sha256 requires manifest")
	}
	return s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var lockRunID string
		if err := tx.QueryRow(ctx, `select capture_run_id from recordings where id=$1`, recordingID).Scan(&lockRunID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(404, "recording_not_found", "unknown recording")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, lockRunID); err != nil {
			return err
		}
		var project uuid.UUID
		var state, runID string
		var durable, sequenceBase int64
		var segmentNo int
		var existingFinal *int64
		var existingManifestSHA []byte
		if err := tx.QueryRow(ctx, `select project_id, state, capture_run_id, segment_no, durable_seq, sequence_base, final_seq, manifest_sha256 from recordings where id=$1 for update`, recordingID).Scan(&project, &state, &runID, &segmentNo, &durable, &sequenceBase, &existingFinal, &existingManifestSHA); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpapi.E(404, "recording_not_found", "unknown recording")
			}
			return err
		}
		if project != p.ProjectID {
			return httpapi.E(403, "forbidden", "recording belongs to another project")
		}
		if state != "open" && state != "sealed" {
			return httpapi.E(409, "recording_sealed", "recording state "+state)
		}
		if req.FinalSeq < durable || req.FinalSeq <= sequenceBase {
			return httpapi.E(409, "final_seq_conflict", "final_seq is below durable evidence or does not contain a segment event")
		}
		runFinal := req.RunFinal == nil || *req.RunFinal
		if runFinal {
			var higherSegmentExists bool
			if err := tx.QueryRow(ctx, `select exists(select 1 from recordings where capture_run_id=$1 and segment_no>$2)`, runID, segmentNo).Scan(&higherSegmentExists); err != nil {
				return err
			}
			if higherSegmentExists {
				return httpapi.E(http.StatusConflict, "final_segment_conflict", "only the highest recording segment can finalize a capture run")
			}
		}
		if state == "sealed" {
			if existingFinal == nil || *existingFinal != req.FinalSeq {
				return httpapi.E(409, "final_seq_conflict", "recording is already sealed at a different final_seq")
			}
			if len(existingManifestSHA) > 0 && len(manifestSHA) > 0 && !bytes.Equal(existingManifestSHA, manifestSHA) {
				return httpapi.E(409, "manifest_conflict", "recording is already sealed with a different manifest")
			}
			if len(existingManifestSHA) == 0 && len(manifestSHA) > 0 {
				if _, err := tx.Exec(ctx, `update recordings set manifest=$2::jsonb, manifest_sha256=$3, updated_at=now() where id=$1`, recordingID, req.Manifest, manifestSHA); err != nil {
					return err
				}
			}
			if runFinal {
				promoted, err := tx.Exec(ctx, `update capture_runs set ended_at=now() where id=$1 and ended_at is null`, runID)
				if err != nil {
					return err
				}
				if promoted.RowsAffected() > 0 {
					if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: project, Type: jobs.TypeCoverage, RecordingID: recordingID, CaptureRunID: runID,
						InputRef: map[string]any{"reason": "seal", "durable_seq": durable, "run_final": true}, ProcessorVersion: "coverage-v3", Priority: 3}); err != nil {
						return err
					}
					return notify.Publish(ctx, tx, project, "recording", recordingID, "sealed", req.FinalSeq)
				}
			}
			return nil
		}
		var manifest any = nil
		if len(req.Manifest) > 0 {
			manifest = req.Manifest
		}
		if _, err := tx.Exec(ctx, `update recordings set state='sealed', final_seq=$2, manifest=coalesce($3::jsonb, manifest), manifest_sha256=coalesce($4, manifest_sha256), sealed_at=now(), updated_at=now() where id=$1`, recordingID, req.FinalSeq, manifest, manifestSHA); err != nil {
			return err
		}
		if runFinal {
			if _, err := tx.Exec(ctx, `update capture_runs set ended_at = coalesce(ended_at, now()) where id=$1`, runID); err != nil {
				return err
			}
		}
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: project, Type: jobs.TypeCoverage, RecordingID: recordingID, CaptureRunID: runID,
			InputRef: map[string]any{"reason": "seal", "durable_seq": durable, "run_final": runFinal}, ProcessorVersion: "coverage-v3", Priority: 3}); err != nil {
			return err
		}
		return notify.Publish(ctx, tx, project, "recording", recordingID, "sealed", req.FinalSeq)
	})
}
