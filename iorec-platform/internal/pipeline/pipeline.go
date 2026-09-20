// Package pipeline implements the worker stages (platform/05): decode,
// assemble, normalize, resolve, coverage, rules. Every stage is idempotent and
// versioned; results carry processor_version and evidence_refs.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/exporter"
	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/notify"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/store"
)

// Processor versions.
const (
	DecoderVersion        = "decoder-v1"
	AssemblerVersion      = "assembler-v2"
	NormalizerVersion     = "normalizer-v6"
	ResolverVersion       = "resolver-v2"
	TransportAuditVersion = "transport-audit-v2"
	CoverageVersion       = "coverage-v4"
	RulesVersion          = "rules-v1"
)

// Deps are stage dependencies.
type Deps struct {
	DB               *store.DB
	Obj              objstore.Store
	TransportDecoder TransportDecoder
}

// EvidenceRef points back to raw events.
type EvidenceRef struct {
	RecordingID string `json:"recording_id"`
	FirstSeq    int64  `json:"first_seq"`
	LastSeq     int64  `json:"last_seq"`
}

// Handle dispatches a leased job.
func (d *Deps) Handle(ctx context.Context, j *jobs.Job) error {
	start := time.Now()
	if j.CaptureRunID != nil {
		var state string
		err := d.DB.Pool.QueryRow(ctx, `select state from capture_runs where id=$1 and project_id=$2`, *j.CaptureRunID, j.ProjectID).Scan(&state)
		if err == nil && state != "active" {
			slog.Info("job cancelled for non-active capture run", "type", j.Type, "id", j.ID, "capture_run_id", *j.CaptureRunID, "state", state)
			return nil
		}
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
	}
	var err error
	switch j.Type {
	case jobs.TypeDecode:
		err = d.Decode(ctx, j)
	case jobs.TypeAssemble:
		err = d.Assemble(ctx, j)
	case jobs.TypeNormalize:
		err = d.Normalize(ctx, j)
	case jobs.TypeResolve:
		err = d.Resolve(ctx, j)
	case jobs.TypeTransportAudit:
		err = d.TransportAudit(ctx, j)
	case jobs.TypeCoverage:
		err = d.Coverage(ctx, j)
	case jobs.TypeRules:
		err = d.Rules(ctx, j)
	case jobs.TypeExport:
		err = (&exporter.Service{DB: d.DB, Obj: d.Obj}).Run(ctx, j)
	default:
		err = fmt.Errorf("unknown job type %q", j.Type)
	}
	slog.Info("job", "type", j.Type, "id", j.ID, "ms", time.Since(start).Milliseconds(), "err", err)
	return err
}

type batchRef struct {
	BatchID   string `json:"batch_id"`
	FirstSeq  int64  `json:"first_seq"`
	LastSeq   int64  `json:"last_seq"`
	Reprocess string `json:"reprocess,omitempty"`
}

func (d *Deps) batchRef(j *jobs.Job) (batchRef, error) {
	var br batchRef
	if err := json.Unmarshal(j.InputRef, &br); err != nil {
		return br, err
	}
	if j.RecordingID == nil {
		return br, fmt.Errorf("job has no recording_id")
	}
	return br, nil
}

// enqueueNext adds a follow-up job in its own transaction.
func (d *Deps) enqueueNext(ctx context.Context, project uuid.UUID, typ, recording, run string, input any, version string, prio int) error {
	return d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `select state='active' from capture_runs where id=$1 and project_id=$2`, run, project).Scan(&active); err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return err
		}
		if !active {
			return nil
		}
		_, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: project, Type: typ, RecordingID: recording, CaptureRunID: run, InputRef: input, ProcessorVersion: version, Priority: prio})
		return err
	})
}

func (d *Deps) publish(ctx context.Context, project uuid.UUID, entityType, id, kind string, rev int64) {
	_ = notify.PublishPool(ctx, d.DB.Pool, project, entityType, id, kind, rev)
}

func runIDOf(j *jobs.Job) string {
	if j.CaptureRunID != nil {
		return *j.CaptureRunID
	}
	return ""
}

// Collector-issued ids are unique only within a capture run. Platform keys scope them by run
// with a URL-safe separator so they can appear in paths.
const keySep = "~"

// AttemptKey is the platform id of an attempt.
func AttemptKey(run, nativeID string) string { return run + keySep + nativeID }

// InferenceKey is the platform id of a logical inference.
func InferenceKey(run, nativeID string) string { return run + keySep + nativeID }

// SessionKey is the platform id of a native agent session.
func SessionKey(run, nativeID string) string { return "sess:" + run + keySep + nativeID }

// TaskKey is a collision-free, run-scoped key for a native task or fallback
// session boundary. The run length disambiguates imported IDs containing the
// separator used by older entity keys.
func TaskKey(run, kind, nativeID string) string {
	return fmt.Sprintf("task:%s:%d:%s:%s", kind, len(run), run, nativeID)
}
