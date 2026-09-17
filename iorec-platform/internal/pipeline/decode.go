package pipeline

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/protocol"
)

// Decode reads a batch object and indexes its events into recording_events.
func (d *Deps) Decode(ctx context.Context, j *jobs.Job) error {
	br, err := d.batchRef(j)
	if err != nil {
		return err
	}
	rec := *j.RecordingID
	var key string
	if err := d.DB.Pool.QueryRow(ctx, `select object_key from batches where recording_id=$1 and batch_id=$2`, rec, br.BatchID).Scan(&key); err != nil {
		return fmt.Errorf("batch row: %w", err)
	}
	rc, err := d.Obj.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("object %s: %w", key, err)
	}
	defer rc.Close()
	hdr, _, raw, err := protocol.ReadBatchBody(rc)
	if err != nil {
		return err
	}
	events, err := protocol.ParseEvents(hdr, raw)
	if err != nil {
		return err
	}
	b := &pgx.Batch{}
	for _, ev := range events {
		var payload any
		if len(ev.Payload) > 0 {
			payload = ev.Payload
		}
		var sha []byte
		var size *int64
		if ev.PayloadRef != nil {
			sha, _ = hex.DecodeString(strings.TrimPrefix(ev.PayloadRef.SHA256, "sha256:"))
			s := ev.PayloadRef.Size
			size = &s
		}
		var red any
		if ev.Redaction != nil {
			red, _ = json.Marshal(ev.Redaction)
		}
		evidence := json.RawMessage(`[]`)
		if len(ev.Evidence) > 0 {
			evidence, _ = json.Marshal(ev.Evidence)
		}
		var rawMediaType string
		var rawTruncated bool
		if ev.PayloadRef != nil {
			rawMediaType = ev.PayloadRef.MediaType
			rawTruncated = ev.PayloadRef.Truncated
		}
		b.Queue(`insert into recording_events(recording_id, seq, event_id, monotonic_ns, wall_time, source, event, task_id, agent_session_id, turn_id, inference_id, attempt_id, connection_id, parent_span_id, pid, container_id, payload, payload_sha256, payload_size, raw_media_type, raw_truncated, redaction, confidence, evidence, terminal_state, batch_id)
			values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26) on conflict (recording_id, seq) do nothing`,
			rec, ev.Seq, ev.EventID, ev.MonotonicNS, ev.WallTime, ev.Source, ev.Event,
			nilIfEmpty(ev.IDs.TaskID), nilIfEmpty(ev.IDs.AgentSessionID), nilIfEmpty(ev.IDs.TurnID), nilIfEmpty(ev.IDs.InferenceID), nilIfEmpty(ev.IDs.AttemptID), nilIfEmpty(ev.IDs.ConnectionID), nilIfEmpty(ev.IDs.ParentSpanID),
			nilIfZero(ev.IDs.PID), nilIfEmpty(ev.IDs.ContainerID), payload, sha, size, nilIfEmpty(rawMediaType), rawTruncated, red, ev.Confidence, evidence, nilIfEmpty(ev.TerminalState), hdr.BatchID)
	}
	res := d.DB.Pool.SendBatch(ctx, b)
	for range events {
		if _, err := res.Exec(); err != nil {
			res.Close()
			return err
		}
	}
	if err := res.Close(); err != nil {
		return err
	}
	// run_start carries agent metadata: reflect onto capture_runs
	for _, ev := range events {
		if (ev.Event == protocol.EvRunStart || ev.Event == protocol.EvRunStarted) && len(ev.Payload) > 0 {
			var p struct {
				Command      json.RawMessage `json:"command"`
				Cwd          string          `json:"cwd"`
				AgentKind    string          `json:"agent_kind"`
				AgentVersion string          `json:"agent_version"`
			}
			_ = json.Unmarshal(ev.Payload, &p)
			_, _ = d.DB.Pool.Exec(ctx, `update capture_runs set command=coalesce(command,$2), cwd=coalesce(cwd,$3), agent_kind=coalesce(agent_kind,$4), agent_version=coalesce(agent_version,$5), started_at=coalesce(started_at,$6) where id=$1`,
				runIDOf(j), nilIfEmpty(commandText(p.Command)), nilIfEmpty(p.Cwd), nilIfEmpty(p.AgentKind), nilIfEmpty(p.AgentVersion), ev.WallTime)
		}
		if (ev.Event == protocol.EvRunEnd || ev.Event == protocol.EvRunFinished) && len(ev.Payload) > 0 {
			var p struct {
				ExitCode *int `json:"exit_code"`
			}
			_ = json.Unmarshal(ev.Payload, &p)
			_, _ = d.DB.Pool.Exec(ctx, `update capture_runs set ended_at=$2, exit_code=coalesce($3, exit_code) where id=$1`, runIDOf(j), ev.WallTime, p.ExitCode)
		}
	}
	if err := d.rebuildCaptureTasks(ctx, j.ProjectID, runIDOf(j)); err != nil {
		return fmt.Errorf("rebuild capture tasks: %w", err)
	}
	return d.enqueueNext(ctx, j.ProjectID, jobs.TypeAssemble, rec, runIDOf(j), br, AssemblerVersion, 9)
}

const (
	taskSplitPolicyV1          = "agent-task-or-session-v1"
	maxCaptureTasks            = 100_000
	maxTaskSessionAssociations = 100_000
)

type captureTaskAccumulator struct {
	id, kind, native    string
	eventCount          int64
	firstSeq, lastSeq   int64
	firstSeen, lastSeen time.Time
	sessions            map[string]struct{}
}

func (d *Deps) rebuildCaptureTasks(ctx context.Context, projectID uuid.UUID, run string) error {
	if run == "" {
		return fmt.Errorf("capture run id is empty")
	}
	return d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, "iorec-capture-tasks:"+run); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `select coalesce(e.task_id,''), coalesce(e.agent_session_id,''), e.seq, e.wall_time
			from recording_events e join recordings r on r.id=e.recording_id
			where r.capture_run_id=$1 and (e.task_id is not null or e.agent_session_id is not null)
			order by e.seq, e.recording_id`, run)
		if err != nil {
			return err
		}
		tasks := make(map[string]*captureTaskAccumulator)
		associations := 0
		for rows.Next() {
			var taskID, sessionID string
			var seq int64
			var at time.Time
			if err := rows.Scan(&taskID, &sessionID, &seq, &at); err != nil {
				rows.Close()
				return err
			}
			kind, native := "agent_task", taskID
			if native == "" {
				kind, native = "agent_session", sessionID
			}
			if native == "" {
				continue
			}
			key := TaskKey(run, kind, native)
			acc := tasks[key]
			if acc == nil {
				if len(tasks) == maxCaptureTasks {
					rows.Close()
					return fmt.Errorf("logical task count exceeds %d", maxCaptureTasks)
				}
				acc = &captureTaskAccumulator{id: key, kind: kind, native: native, firstSeq: seq, firstSeen: at, sessions: make(map[string]struct{})}
				tasks[key] = acc
			}
			acc.eventCount++
			acc.lastSeq, acc.lastSeen = seq, at
			if sessionID != "" {
				if _, exists := acc.sessions[sessionID]; !exists {
					if associations == maxTaskSessionAssociations {
						rows.Close()
						return fmt.Errorf("task/session association count exceeds %d", maxTaskSessionAssociations)
					}
					acc.sessions[sessionID] = struct{}{}
					associations++
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, task := range tasks {
			sessions := make([]string, 0, len(task.sessions))
			for session := range task.sessions {
				sessions = append(sessions, session)
			}
			sort.Strings(sessions)
			sessionJSON, err := json.Marshal(sessions)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `insert into capture_tasks(id,project_id,capture_run_id,split_policy,boundary_kind,native_id,session_ids,event_count,first_seq,last_seq,first_seen_at,last_seen_at)
				values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
				on conflict(id) do update set session_ids=excluded.session_ids,event_count=excluded.event_count,first_seq=excluded.first_seq,last_seq=excluded.last_seq,first_seen_at=excluded.first_seen_at,last_seen_at=excluded.last_seen_at,updated_at=now()`,
				task.id, projectID, run, taskSplitPolicyV1, task.kind, task.native, sessionJSON, task.eventCount, task.firstSeq, task.lastSeq, task.firstSeen, task.lastSeen); err != nil {
				return err
			}
		}
		return nil
	})
}

func commandText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		return strings.Join(argv, " ")
	}
	return ""
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilIfZero(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}
