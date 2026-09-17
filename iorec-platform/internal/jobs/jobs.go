// Package jobs implements the PostgreSQL-backed processing job queue
// (lease, retry, dedupe) described in platform/05 §2.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Job types.
const (
	TypeDecode         = "decode"
	TypeAssemble       = "assemble"
	TypeNormalize      = "normalize"
	TypeResolve        = "resolve"
	TypeTransportAudit = "transport_audit"
	TypeCoverage       = "coverage"
	TypeRules          = "rules"
	TypeEval           = "eval"
	TypeExport         = "export"
)

// Statuses.
const (
	StatusPending = "pending"
	StatusLeased  = "leased"
	StatusDone    = "done"
	StatusFailed  = "failed"
	StatusDead    = "dead"
)

// MaxAttempts before a job is marked dead.
const MaxAttempts = 5

// Job is a queue row.
type Job struct {
	ID               uuid.UUID
	ProjectID        uuid.UUID
	Type             string
	RecordingID      *string
	CaptureRunID     *string
	InputRef         json.RawMessage
	ProcessorVersion string
	DedupeKey        string
	Attempts         int
	Priority         int
}

// Spec describes a job to enqueue.
type Spec struct {
	ProjectID        uuid.UUID
	Type             string
	RecordingID      string
	CaptureRunID     string
	InputRef         any
	ProcessorVersion string
	Priority         int
}

// DedupeKey builds the unique key: type + input + version.
func DedupeKey(s Spec) string {
	b, _ := json.Marshal(s.InputRef)
	return fmt.Sprintf("%s|%s|%s|%s|%s", s.Type, s.RecordingID, s.CaptureRunID, string(b), s.ProcessorVersion)
}

// Enqueue inserts a job inside tx; duplicates are ignored. Returns true if inserted.
func Enqueue(ctx context.Context, tx pgx.Tx, s Spec) (bool, error) {
	b, err := json.Marshal(s.InputRef)
	if err != nil {
		return false, err
	}
	var rec, run *string
	if s.RecordingID != "" {
		rec = &s.RecordingID
	}
	if s.CaptureRunID != "" {
		run = &s.CaptureRunID
	}
	tag, err := tx.Exec(ctx, `insert into processing_jobs (id, project_id, type, recording_id, capture_run_id, input_ref, processor_version, dedupe_key, priority)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9) on conflict (dedupe_key) do nothing`,
		uuid.New(), s.ProjectID, s.Type, rec, run, b, s.ProcessorVersion, DedupeKey(s), s.Priority)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Queue leases and completes jobs.
type Queue struct {
	Pool     *pgxpool.Pool
	Owner    string
	LeaseFor time.Duration
}

// Lease takes one ready job of the given types (any if empty).
func (q *Queue) Lease(ctx context.Context, types []string) (*Job, error) {
	lease := q.LeaseFor
	if lease == 0 {
		lease = 5 * time.Minute
	}
	row := q.Pool.QueryRow(ctx, `
		with cand as (
			select id from processing_jobs
			where (status = 'pending' or (status = 'leased' and lease_until < now()))
			  and (cardinality($2::text[]) = 0 or type = any($2))
			order by priority desc, created_at
			for update skip locked limit 1
		)
		update processing_jobs j set status='leased', lease_owner=$1, lease_until=now()+$3::interval,
			attempts = attempts + 1, started_at = coalesce(started_at, now())
		from cand where j.id = cand.id
		returning j.id, j.project_id, j.type, j.recording_id, j.capture_run_id, j.input_ref, j.processor_version, j.dedupe_key, j.attempts, j.priority`,
		q.Owner, types, lease)
	var j Job
	if err := row.Scan(&j.ID, &j.ProjectID, &j.Type, &j.RecordingID, &j.CaptureRunID, &j.InputRef, &j.ProcessorVersion, &j.DedupeKey, &j.Attempts, &j.Priority); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &j, nil
}

// Renew extends the lease.
func (q *Queue) Renew(ctx context.Context, id uuid.UUID) error {
	_, err := q.Pool.Exec(ctx, `update processing_jobs set lease_until = now() + $2::interval where id=$1 and lease_owner=$3`, id, q.LeaseFor, q.Owner)
	return err
}

// Complete marks done.
func (q *Queue) Complete(ctx context.Context, id uuid.UUID) error {
	_, err := q.Pool.Exec(ctx, `update processing_jobs set status='done', finished_at=now(), lease_owner=null, lease_until=null, last_error=null where id=$1`, id)
	return err
}

// Fail records the error; retries with backoff or marks dead.
func (q *Queue) Fail(ctx context.Context, j *Job, cause error) error {
	msg := cause.Error()
	if len(msg) > 4000 {
		msg = msg[:4000]
	}
	if j.Attempts >= MaxAttempts {
		_, err := q.Pool.Exec(ctx, `update processing_jobs set status='dead', last_error=$2, finished_at=now(), lease_owner=null where id=$1`, j.ID, msg)
		return err
	}
	backoff := time.Duration(math.Pow(2, float64(j.Attempts))) * 5 * time.Second
	_, err := q.Pool.Exec(ctx, `update processing_jobs set status='leased', last_error=$2, lease_until=now()+$3::interval where id=$1`, j.ID, msg, backoff)
	return err
}

// Retry resets a failed/dead job to pending.
func Retry(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	_, err := pool.Exec(ctx, `update processing_jobs set status='pending', attempts=0, last_error=null, lease_owner=null, lease_until=null where id=$1 and status in ('dead','failed','leased')`, id)
	return err
}
