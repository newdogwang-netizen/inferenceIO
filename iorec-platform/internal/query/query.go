// Package query exposes read models for the console (platform/08).
package query

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/pipeline"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/heidihealth/iorec-platform/internal/store"
)

// Service holds dependencies.
type Service struct{ DB *store.DB }

func pathParam(r *http.Request, name string) string {
	raw := chi.URLParam(r, name)
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func limitParam(r *http.Request, def, max int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		if v > max {
			return max
		}
		return v
	}
	return def
}

// rowsToMaps converts a result set into JSON-friendly maps.
func rowsToMaps(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	fds := rows.FieldDescriptions()
	var out []map[string]any
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		m := make(map[string]any, len(fds))
		for i, fd := range fds {
			v := vals[i]
			switch x := v.(type) {
			case []byte:
				m[string(fd.Name)] = hex.EncodeToString(x)
			case [16]byte:
				m[string(fd.Name)] = uuid.UUID(x).String()
			default:
				m[string(fd.Name)] = v
			}
		}
		out = append(out, m)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, rows.Err()
}

func (s *Service) one(ctx context.Context, q string, args ...any) (map[string]any, error) {
	rows, err := s.DB.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	ms, err := rowsToMaps(rows)
	if err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, httpapi.E(404, "not_found", "no such entity")
	}
	return ms[0], nil
}

func (s *Service) list(ctx context.Context, q string, args ...any) ([]map[string]any, error) {
	rows, err := s.DB.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return rowsToMaps(rows)
}

func requireViewer(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	p, err := httpapi.RequireUser(r, auth.RoleViewer)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return p, false
	}
	return p, true
}

// ---- recordings & runs ----

func (s *Service) ListRecordings(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	limit := limitParam(r, 50, 500)
	cursor := r.URL.Query().Get("cursor")
	items, err := s.list(r.Context(), `select r.id, r.capture_run_id, r.segment_no, r.sequence_base, r.state, r.origin, r.durable_seq, r.parsed_seq, r.final_seq,
			case when c.state='active' and r.state not in ('deleting','deleted') then r.coverage->>'claim' end as coverage_claim,
			case when c.state='active' and r.state not in ('deleting','deleted') then r.missing_blobs else '[]'::jsonb end as missing_blobs,
			case when c.state='active' and r.state not in ('deleting','deleted') then r.integrity_alerts else '[]'::jsonb end as integrity_alerts,
			r.created_at, r.updated_at, r.sealed_at,
			case when c.state='active' and r.state not in ('deleting','deleted') then c.agent_kind end as agent_kind,
			case when c.state='active' and r.state not in ('deleting','deleted') then c.agent_version end as agent_version,
			case when c.state='active' and r.state not in ('deleting','deleted') then c.command end as command,
			case when c.state='active' and r.state not in ('deleting','deleted') then c.relation_revision else 0 end as relation_revision,
			case when c.state='active' and r.state not in ('deleting','deleted') then c.analysis_revision else 0 end as analysis_revision,
			case when c.state='active' and r.state not in ('deleting','deleted') then (select count(*) from model_attempts a where a.recording_id=r.id) else 0 end as attempt_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then token_usage.model_call_count end as model_call_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then token_usage.input_token_count end as input_token_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then token_usage.input_token_call_count end as input_token_call_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then token_usage.output_token_count end as output_token_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then token_usage.output_token_call_count end as output_token_call_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then (select count(*) from model_attempts a where a.recording_id=r.id and a.project_id=r.project_id and a.entity_kind='websocket_connection') end as websocket_connection_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then (select count(*) from model_attempts a where a.recording_id=r.id and a.project_id=r.project_id and a.source like 'hook:%') end as hook_observation_count,
			case when c.state='active' and r.state not in ('deleting','deleted','expired','expiring') then (select count(*) from recording_events e where e.recording_id=r.id and e.event in ('sse_event','websocket_frame')) end as stream_event_count,
			case when c.state='active' and r.state not in ('deleting','deleted') then (select count(*) from processing_jobs pj where pj.recording_id=r.id and pj.status in ('dead','failed')) else 0 end as failed_jobs,
			case when c.state='active' and r.state not in ('deleting','deleted') then (select count(*) from processing_jobs pj where pj.recording_id=r.id and pj.status in ('pending','leased')) else 0 end as active_jobs
		from recordings r join capture_runs c on c.id=r.capture_run_id
		left join lateral (
			select count(*)::bigint as model_call_count,
				sum(token_values.input_tokens)::bigint as input_token_count,
				count(token_values.input_tokens)::bigint as input_token_call_count,
				sum(token_values.output_tokens)::bigint as output_token_count,
				count(token_values.output_tokens)::bigint as output_token_call_count
			from (
				select `+inputTokenValueExpr+` as input_tokens, `+outputTokenValueExpr+` as output_tokens
				from model_attempts a
				where a.recording_id=r.id and a.project_id=r.project_id and c.state='active'
					and r.state not in ('deleting','deleted','expired','expiring') and (`+modelCallPredicate+`)
			) token_values
		) token_usage on true
		where r.project_id=$1 and ($2 = '' or r.created_at < (select created_at from recordings where id=$2 and project_id=$1)) order by r.created_at desc limit $3`, p.ProjectID, cursor, limit)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	for _, it := range items {
		it["ui_state"] = uiState(it)
	}
	next := ""
	if len(items) == limit {
		next, _ = items[len(items)-1]["id"].(string)
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

// uiState derives the four-state display (platform/04 §6).
func uiState(it map[string]any) string {
	state, _ := it["state"].(string)
	durable, _ := it["durable_seq"].(int64)
	parsed, _ := it["parsed_seq"].(int64)
	failed, _ := it["failed_jobs"].(int64)
	active, _ := it["active_jobs"].(int64)
	switch {
	case failed > 0 && parsed < durable:
		return "parse_blocked"
	case state == "open":
		return "uploading"
	case state == "deleting":
		return "deleting"
	case state == "deleted":
		return "deleted"
	case state == "expiring":
		return "expiring"
	case state == "expired":
		return "evidence_expired"
	case parsed < durable || active > 0:
		return "analyzing"
	default:
		return "archived"
	}
}

func (s *Service) GetRecording(w http.ResponseWriter, r *http.Request) {
	p := httpapi.Principal(r)
	id := pathParam(r, "id")
	if p.Kind == auth.KindCollector {
		query := `select r.id, r.capture_run_id, r.segment_no, r.sequence_base, r.state, r.durable_seq, r.final_seq, r.updated_at
			from recordings r join capture_runs c on c.id=r.capture_run_id
			where r.id=$1 and r.project_id=$2 and c.collector_id is null`
		args := []any{id, p.ProjectID}
		if p.CollectorID != uuid.Nil {
			query = `select r.id, r.capture_run_id, r.segment_no, r.sequence_base, r.state, r.durable_seq, r.final_seq, r.updated_at
				from recordings r join capture_runs c on c.id=r.capture_run_id
				where r.id=$1 and r.project_id=$2 and c.collector_id=$3`
			args = append(args, p.CollectorID)
		}
		item, err := s.one(r.Context(), query, args...)
		if err != nil {
			httpapi.WriteError(w, r, httpapi.E(404, "not_found", "unknown recording for this collector"))
			return
		}
		httpapi.WriteJSON(w, 200, item)
		return
	}
	var ok bool
	p, ok = requireViewer(w, r)
	if !ok {
		return
	}
	it, err := s.one(r.Context(), `select r.*, c.agent_kind, c.agent_version, c.command, c.cwd, c.started_at as run_started_at, c.ended_at as run_ended_at, c.exit_code, c.relation_revision, c.analysis_revision, c.metadata as run_metadata, c.transport_proof, c.transport_proof_revision,c.benchmark_result,
			(select count(*) from model_attempts a where a.recording_id=r.id) as attempt_count,
			(select count(*) from model_inferences i where i.recording_id=r.id) as inference_count,
			token_usage.model_call_count, token_usage.input_token_count, token_usage.input_token_call_count,
			token_usage.output_token_count, token_usage.output_token_call_count,
			(select count(*) from processing_jobs pj where pj.recording_id=r.id and pj.status in ('dead','failed')) as failed_jobs,
			(select count(*) from processing_jobs pj where pj.recording_id=r.id and pj.status in ('pending','leased')) as active_jobs,
			(select coalesce(json_agg(json_build_object('batch_id',b.batch_id,'first_seq',b.first_seq,'last_seq',b.last_seq,'received_at',b.received_at,'parsed_at',b.parsed_at) order by b.first_seq), '[]'::json) from batches b where b.recording_id=r.id) as batches
		from recordings r join capture_runs c on c.id=r.capture_run_id
		left join lateral (
			select count(*)::bigint as model_call_count,
				sum(token_values.input_tokens)::bigint as input_token_count,
				count(token_values.input_tokens)::bigint as input_token_call_count,
				sum(token_values.output_tokens)::bigint as output_token_count,
				count(token_values.output_tokens)::bigint as output_token_call_count
			from (
				select `+inputTokenValueExpr+` as input_tokens, `+outputTokenValueExpr+` as output_tokens
				from model_attempts a
				where a.recording_id=r.id and a.project_id=r.project_id and (`+modelCallPredicate+`)
			) token_values
		) token_usage on true
		where r.id=$1 and r.project_id=$2 and c.state='active' and r.state not in ('deleting','deleted')`, id, p.ProjectID)
	if err != nil {
		// Deleting and deleted entities remain discoverable as minimal
		// tombstones, but sensitive run, batch, and analysis fields are fenced
		// as soon as the deletion request is accepted.
		it, err = s.one(r.Context(), `select r.id,r.capture_run_id,r.segment_no,r.sequence_base,r.state,r.created_at,r.updated_at,r.deletion_started_at,r.deleted_at,r.deleted_by,c.state as run_state,0::bigint as attempt_count,0::bigint as inference_count,0::bigint as failed_jobs,0::bigint as active_jobs,'[]'::json as batches from recordings r join capture_runs c on c.id=r.capture_run_id where r.id=$1 and r.project_id=$2 and (c.state<>'active' or r.state in ('deleting','deleted'))`, id, p.ProjectID)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
	}
	it["ui_state"] = uiState(it)
	httpapi.WriteJSON(w, 200, it)
}

func (s *Service) ListRuns(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	items, err := s.list(r.Context(), `select c.id,c.project_id,c.state,c.retention_until,c.deleted_at,c.deleted_by,c.created_at,
		case when c.state='active' then c.collector_id end as collector_id,
		case when c.state='active' then c.command end as command,
		case when c.state='active' then c.cwd end as cwd,
		case when c.state='active' then c.agent_kind end as agent_kind,
		case when c.state='active' then c.agent_version end as agent_version,
		case when c.state='active' then c.started_at end as started_at,
		case when c.state='active' then c.ended_at end as ended_at,
		case when c.state='active' then c.exit_code end as exit_code,
		case when c.state='active' then c.metadata else '{}'::jsonb end as metadata,
		case when c.state='active' then c.relation_revision else 0 end as relation_revision,
		case when c.state='active' then c.analysis_revision else 0 end as analysis_revision,
		case when c.state='active' then c.transport_proof end as transport_proof,
		case when c.state='active' then c.transport_proof_revision else 0 end as transport_proof_revision,
		case when c.state='active' then (select count(*) from recordings r where r.capture_run_id=c.id) else 0 end as recording_count,
		case when c.state='active' then (select count(*) from model_inferences i where i.capture_run_id=c.id) else 0 end as inference_count
		from capture_runs c where c.project_id=$1 order by c.created_at desc limit $2`, p.ProjectID, limitParam(r, 50, 500))
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items})
}

// ---- timeline ----

func (s *Service) Timeline(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	id := pathParam(r, "id")
	var run string
	var rev int64
	var claim *string
	err := s.DB.Pool.QueryRow(r.Context(), `select r.capture_run_id, c.relation_revision, r.coverage->>'claim' from recordings r join capture_runs c on c.id=r.capture_run_id where r.id=$1 and r.project_id=$2 and c.state='active' and r.state not in ('deleting','deleted')`, id, p.ProjectID).Scan(&run, &rev, &claim)
	if errors.Is(err, pgx.ErrNoRows) {
		httpapi.WriteError(w, r, httpapi.E(404, "not_found", "unknown recording"))
		return
	}
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	sessions, err := s.list(r.Context(), `select id, kind, native_id, role, parent_session_id, turns, inference_count, first_seen_at, last_seen_at from sessions where capture_run_id=$1 and project_id=$2 and superseded=false order by first_seen_at`, run, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	tasks, err := s.list(r.Context(), `select id, split_policy, boundary_kind, native_id, session_ids, event_count, first_seq, last_seq, first_seen_at, last_seen_at from capture_tasks where capture_run_id=$1 and project_id=$2 order by first_seq, id`, run, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	infs, err := s.list(r.Context(), `select i.id, i.status, i.attempt_count, i.first_attempt_at, i.model, i.api_mode, i.task_id, i.session_id, i.turn_id, i.server_state, i.usage,
			left(i.normalized->>'response_text', 200) as response_preview, i.normalized->>'finish_reason' as finish_reason,
			case when jsonb_typeof(i.normalized->'messages')='array' then jsonb_array_length(i.normalized->'messages') else 0 end as message_count,
			(select rel.confidence from relations rel where rel.from_id=i.id and rel.project_id=$2 and rel.type='belongs_to_turn' and rel.superseded_by is null order by rel.revision desc limit 1) as confidence,
			(select rel.status from relations rel where rel.from_id=i.id and rel.project_id=$2 and rel.type='belongs_to_turn' and rel.superseded_by is null order by rel.revision desc limit 1) as relation_status,
			(select coalesce(json_agg(json_build_object('id',a.id,'terminal_state',a.terminal_state,'status_code',a.status_code,'provider_host',a.provider_host,'started_at',a.started_at,'ended_at',a.ended_at,'sse_event_count',a.sse_event_count) order by a.started_at),'[]'::json) from model_attempts a where a.inference_id=i.id and a.project_id=$2) as attempts
		from model_inferences i where i.capture_run_id=$1 and i.project_id=$2 order by i.first_attempt_at`, run, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	unattributed, err := s.list(r.Context(), `select id, task_id, session_id, provider_host, started_at, terminal_state, status_code, api_mode from model_attempts where capture_run_id=$1 and project_id=$2 and inference_id is null and entity_kind<>'websocket_connection' order by started_at`, run, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	lifecycle, err := s.list(r.Context(), `select e.recording_id, e.seq, e.wall_time, e.source, e.event, e.task_id, e.agent_session_id, e.turn_id, e.parent_span_id, e.payload
		from recording_events e join recordings r on r.id=e.recording_id
		where r.capture_run_id=$1 and r.project_id=$2 and e.event in ('run_start','run_end','session_start','session_end','turn_start','turn_end','tool_call','tool_result','subagent_start','subagent_stop','compaction','gap','unknown_egress','capability_report','manifest')
		order by e.seq, e.recording_id limit 5000`, run, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"recording_id": id, "capture_run_id": run, "relation_revision": rev, "coverage_claim": claim, "tasks": tasks, "sessions": sessions, "inferences": infs, "unattributed_attempts": unattributed, "lifecycle": lifecycle})
}

// ---- attempts ----

func (s *Service) ListAttempts(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	items, err := s.list(r.Context(), `select a.id, a.recording_id, a.capture_run_id, a.inference_id, a.source, a.api_mode, a.model, a.provider_host, a.method, a.url, a.started_at, a.ended_at, a.first_byte_at, a.terminal_state, a.status_code, a.error_class, a.sse_event_count, a.usage, a.pid, a.first_seq, a.last_seq, a.entity_kind, a.parent_attempt_id, a.projection
		from model_attempts a join capture_runs c on c.id=a.capture_run_id and c.project_id=a.project_id join recordings rec on rec.id=a.recording_id and rec.project_id=a.project_id
		where a.project_id=$1 and c.state='active' and rec.state not in ('deleting','deleted') and ($2='' or a.recording_id=$2) and ($3='' or a.capture_run_id=$3) and ($4='' or a.inference_id=$4) order by a.started_at desc limit $5`,
		p.ProjectID, q.Get("recording_id"), q.Get("capture_run_id"), q.Get("inference_id"), limitParam(r, 200, 2000))
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items})
}

func (s *Service) GetAttempt(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	id := pathParam(r, "id")
	it, err := s.one(r.Context(), `select a.* from model_attempts a join capture_runs c on c.id=a.capture_run_id and c.project_id=a.project_id join recordings rec on rec.id=a.recording_id and rec.project_id=a.project_id where a.id=$1 and a.project_id=$2 and c.state='active' and rec.state not in ('deleting','deleted')`, id, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	run, _ := it["capture_run_id"].(string)
	native, _ := it["native_id"].(string)
	child := it["entity_kind"] == "websocket_call"
	parentID := id
	if child {
		parentID, _ = it["parent_attempt_id"].(string)
		parent, err := s.one(r.Context(), `select id,native_id,recording_id,terminal_state,error_class,projection,processor_version from model_attempts where id=$1 and project_id=$2`, parentID, p.ProjectID)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		it["parent_connection"] = parent
		native, _ = parent["native_id"].(string)
	} else if it["entity_kind"] == "websocket_connection" {
		calls, err := s.list(r.Context(), `select id,inference_id,started_at,ended_at,terminal_state,model,usage,projection,evidence_refs from model_attempts where parent_attempt_id=$1 and project_id=$2 order by first_seq,id`, id, p.ProjectID)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		it["calls"] = calls
	}
	if r.URL.Query().Get("view") != "normalized" {
		after, err := eventCursor(r)
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		scope := attemptEventScope{Project: p.ProjectID, Run: run, Native: native, Parent: parentID, ID: id, Child: child}
		page, err := s.attemptEvents(r.Context(), scope, after, limitParam(r, 200, 1000), "all")
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		it["events"] = page.Items
		it["events_page"] = map[string]any{"total": page.Total, "has_more": page.HasMore, "next_after_seq": page.NextAfterSeq, "limit": page.Limit}
		bodies, err := s.attemptEvents(r.Context(), scope, after, limitParam(r, 200, 1000), "body")
		if err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
		requestParts, responseParts := []map[string]any{}, []map[string]any{}
		for _, e := range bodies.Items {
			part := map[string]any{"recording_id": e["recording_id"], "seq": e["seq"], "event": e["event"], "direction": e["direction"], "sha256": e["payload_sha256"], "size": e["payload_size"], "media_type": e["raw_media_type"], "raw_truncated": e["raw_truncated"]}
			if payload, ok := e["payload"].(map[string]any); ok {
				part["chunk_sequence"] = payload["chunk_sequence"]
			}
			if e["event"] == protocol.EvRequestBodyChunk || e["direction"] == "client_to_upstream" {
				requestParts = append(requestParts, part)
			} else {
				responseParts = append(responseParts, part)
			}
		}
		it["request_body_parts"], it["response_body_parts"] = requestParts, responseParts
		it["body_parts_page"] = map[string]any{"total": bodies.Total, "has_more": bodies.HasMore, "next_after_seq": bodies.NextAfterSeq, "limit": bodies.Limit}
	}
	proof, err := s.one(r.Context(), `select c.transport_proof,c.transport_proof_revision,c.benchmark_result,r.coverage,r.coverage_revision from recordings r join capture_runs c on c.id=r.capture_run_id and c.project_id=r.project_id where r.id=$1 and r.project_id=$2 and c.state='active' and r.state not in ('deleting','deleted')`, it["recording_id"], p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	it["evidence_context"] = proof
	rels, err := s.list(r.Context(), `select type, to_id, status, confidence, evidence, revision from relations where from_id=$1 and project_id=$2 and superseded_by is null order by revision desc`, id, p.ProjectID)
	if err == nil {
		it["relations"] = rels
	}
	if p.Kind == auth.KindUser {
		if _, err := s.DB.Pool.Exec(r.Context(), `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'attempt.read','attempt',$3,$4)`, p.ProjectID, p.Subject, id, map[string]any{"view": r.URL.Query().Get("view")}); err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
	}
	httpapi.WriteJSON(w, 200, it)
}

// ---- inferences ----

func (s *Service) GetInference(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	id := pathParam(r, "id")
	it, err := s.one(r.Context(), `select i.* from model_inferences i join capture_runs c on c.id=i.capture_run_id and c.project_id=i.project_id join recordings rec on rec.id=i.recording_id and rec.project_id=i.project_id where i.id=$1 and i.project_id=$2 and c.state='active' and rec.state not in ('deleting','deleted')`, id, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	attempts, _ := s.list(r.Context(), `select id, terminal_state, status_code, provider_host, started_at, ended_at, sse_event_count, error_class, api_mode, model,entity_kind,parent_attempt_id,projection,evidence_refs from model_attempts where inference_id=$1 and project_id=$2 order by started_at`, id, p.ProjectID)
	it["attempts"] = attempts
	rels, _ := s.list(r.Context(), `select type, from_id, to_id, status, confidence, evidence, revision from relations where (from_id=$1 or to_id=$1) and project_id=$2 and superseded_by is null order by revision desc`, id, p.ProjectID)
	it["relations"] = rels
	// diff vs previous in the chain ("follows" relation)
	var prevID string
	if err := s.DB.Pool.QueryRow(r.Context(), `select to_id from relations where from_id=$1 and project_id=$2 and type='follows' and superseded_by is null order by revision desc limit 1`, id, p.ProjectID).Scan(&prevID); err == nil {
		var a, b json.RawMessage
		_ = s.DB.Pool.QueryRow(r.Context(), `select normalized from model_inferences where id=$1 and project_id=$2`, prevID, p.ProjectID).Scan(&a)
		_ = s.DB.Pool.QueryRow(r.Context(), `select normalized from model_inferences where id=$1 and project_id=$2`, id, p.ProjectID).Scan(&b)
		var na, nb pipeline.Normalized
		if json.Unmarshal(a, &na) == nil && json.Unmarshal(b, &nb) == nil {
			it["input_diff"] = pipeline.ComputeInputDiff(prevID, id, &na, &nb)
		}
	}
	httpapi.WriteJSON(w, 200, it)
}

// ---- sessions ----

func (s *Service) GetSession(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	id := pathParam(r, "id")
	it, err := s.one(r.Context(), `select sess.* from sessions sess join capture_runs c on c.id=sess.capture_run_id and c.project_id=sess.project_id where sess.id=$1 and sess.project_id=$2 and c.state='active'`, id, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	children, _ := s.list(r.Context(), `select id, kind, role, inference_count, first_seen_at from sessions where parent_session_id=$1 and project_id=$2 and superseded=false`, id, p.ProjectID)
	it["children"] = children
	infs, _ := s.list(r.Context(), `select id, status, attempt_count, first_attempt_at, model, turn_id, left(normalized->>'response_text',200) as response_preview from model_inferences where session_id=$1 and project_id=$2 order by first_attempt_at`, id, p.ProjectID)
	it["inferences"] = infs
	rels, _ := s.list(r.Context(), `select type, from_id, to_id, status, confidence, evidence from relations where (from_id=$1 or to_id=$1) and project_id=$2 and superseded_by is null`, id, p.ProjectID)
	it["relations"] = rels
	httpapi.WriteJSON(w, 200, it)
}

// ---- findings ----

func (s *Service) ListFindings(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	items, err := s.list(r.Context(), `select f.* from findings f left join capture_runs c on c.id=f.capture_run_id and c.project_id=f.project_id where f.project_id=$1 and (f.capture_run_id is null or c.state='active') and ($2='' or f.capture_run_id=$2) and ($3='' or f.recording_id=$3) and ($4='' or f.status=$4) order by case f.severity when 'high' then 0 when 'warn' then 1 else 2 end, f.created_at desc limit $5`,
		p.ProjectID, q.Get("capture_run_id"), q.Get("recording_id"), q.Get("status"), limitParam(r, 200, 1000))
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items})
}

func (s *Service) ReviewFinding(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleReviewer)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id := pathParam(r, "id")
	var body struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := httpapi.DecodeJSON(r, &body, 1<<16); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if body.Status != "confirmed" && body.Status != "dismissed" && body.Status != "open" {
		httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "status must be confirmed|dismissed|open"))
		return
	}
	if len(body.Note) > 16<<10 || strings.ContainsRune(body.Note, '\x00') {
		httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "review note is invalid"))
		return
	}
	err = s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `update findings f set status=$3, reviewed_by=$4, reviewed_at=now(), review_note=$5 from capture_runs c where f.id=$1 and f.project_id=$2 and c.id=f.capture_run_id and c.project_id=f.project_id and c.state='active'`, id, p.ProjectID, body.Status, p.Subject, body.Note)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.E(404, "not_found", "unknown finding")
		}
		if _, err := tx.Exec(r.Context(), `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'finding.review','finding',$3,$4)`, p.ProjectID, p.Subject, id, map[string]any{"status": body.Status, "note": body.Note}); err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), `insert into notifications_outbox(project_id, entity_type, entity_id, kind) values($1,'finding',$2,$3)`, p.ProjectID, id, body.Status)
		return err
	})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"id": id, "status": body.Status})
}

// ---- jobs ----

func (s *Service) ListJobs(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	items, err := s.list(r.Context(), `select id, type, recording_id, capture_run_id, input_ref, processor_version, status, attempts, last_error, priority, created_at, started_at, finished_at, lease_until from processing_jobs where project_id=$1 and ($2='' or status=$2) and ($3='' or recording_id=$3) order by created_at desc limit $4`,
		p.ProjectID, q.Get("status"), q.Get("recording_id"), limitParam(r, 100, 1000))
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	stats, _ := s.list(r.Context(), `select type, status, count(*) as n from processing_jobs where project_id=$1 group by type, status order by type, status`, p.ProjectID)
	httpapi.WriteJSON(w, 200, map[string]any{"items": items, "stats": stats})
}

func (s *Service) RetryJob(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleOperator)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "bad job id"))
		return
	}
	if err := s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `update processing_jobs j set status='pending', attempts=0, last_error=null, lease_owner=null, lease_until=null from capture_runs c where j.id=$1 and j.project_id=$2 and j.status in ('dead','failed') and c.id=j.capture_run_id and c.project_id=j.project_id and c.state='active'`, id, p.ProjectID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpapi.E(404, "not_found", "unknown retryable job")
		}
		_, err = tx.Exec(r.Context(), `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'job.retry','processing_job',$3,'{}'::jsonb)`, p.ProjectID, p.Subject, id.String())
		return err
	}); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"id": id, "status": "pending"})
}

// CreateJob enqueues a reprocessing job (platform/08 §2).
func (s *Service) CreateJob(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleOperator)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	var body struct {
		Type             string `json:"type"`
		RecordingID      string `json:"recording_id"`
		CaptureRunID     string `json:"capture_run_id"`
		ProcessorVersion string `json:"processor_version"`
		Priority         int    `json:"priority"`
	}
	if err := httpapi.DecodeJSON(r, &body, 1<<16); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if body.ProcessorVersion == "" {
		body.ProcessorVersion = map[string]string{jobs.TypeDecode: pipeline.DecoderVersion, jobs.TypeResolve: pipeline.ResolverVersion, jobs.TypeTransportAudit: pipeline.TransportAuditVersion, jobs.TypeCoverage: pipeline.CoverageVersion, jobs.TypeRules: pipeline.RulesVersion}[body.Type]
	}
	if len(body.ProcessorVersion) > 256 || strings.ContainsAny(body.ProcessorVersion, "\x00\r\n") ||
		len(body.RecordingID) > 240 || strings.ContainsAny(body.RecordingID, "\x00\r\n") ||
		len(body.CaptureRunID) > 256 || strings.ContainsAny(body.CaptureRunID, "\x00\r\n") ||
		body.Priority < -100 || body.Priority > 100 {
		httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "processor_version or priority is invalid"))
		return
	}
	reprocess := uuid.NewString()
	ctx := r.Context()
	var created int
	err = s.DB.Tx(ctx, func(tx pgx.Tx) error {
		switch body.Type {
		case jobs.TypeDecode:
			// re-decode every batch of a recording
			if body.RecordingID == "" {
				return httpapi.E(400, "malformed_request", "recording_id required for decode")
			}
			var run string
			if err := tx.QueryRow(ctx, `select r.capture_run_id from recordings r join capture_runs c on c.id=r.capture_run_id where r.id=$1 and r.project_id=$2 and c.state='active' and r.state in ('open','sealed')`, body.RecordingID, p.ProjectID).Scan(&run); err != nil {
				return httpapi.E(404, "not_found", "unknown recording")
			}
			rows, err := tx.Query(ctx, `select batch_id, first_seq, last_seq from batches where recording_id=$1 order by first_seq`, body.RecordingID)
			if err != nil {
				return err
			}
			type b struct {
				id     string
				fs, ls int64
			}
			var bs []b
			for rows.Next() {
				var x b
				if err := rows.Scan(&x.id, &x.fs, &x.ls); err != nil {
					rows.Close()
					return err
				}
				bs = append(bs, x)
			}
			rows.Close()
			for _, x := range bs {
				ok, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: p.ProjectID, Type: jobs.TypeDecode, RecordingID: body.RecordingID, CaptureRunID: run, InputRef: map[string]any{"batch_id": x.id, "first_seq": x.fs, "last_seq": x.ls, "reprocess": reprocess}, ProcessorVersion: body.ProcessorVersion, Priority: body.Priority})
				if err != nil {
					return err
				}
				if ok {
					created++
				}
			}
		case jobs.TypeResolve, jobs.TypeTransportAudit, jobs.TypeRules:
			if body.CaptureRunID == "" {
				return httpapi.E(400, "malformed_request", "capture_run_id required")
			}
			var owner uuid.UUID
			if err := tx.QueryRow(ctx, `select project_id from capture_runs where id=$1 and state='active'`, body.CaptureRunID).Scan(&owner); err != nil || owner != p.ProjectID {
				return httpapi.E(404, "not_found", "unknown capture run")
			}
			ok, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: p.ProjectID, Type: body.Type, CaptureRunID: body.CaptureRunID, InputRef: map[string]any{"reprocess": reprocess}, ProcessorVersion: body.ProcessorVersion, Priority: body.Priority})
			if err != nil {
				return err
			}
			if ok {
				created++
			}
		case jobs.TypeCoverage:
			if body.RecordingID == "" {
				return httpapi.E(400, "malformed_request", "recording_id required")
			}
			var run string
			if err := tx.QueryRow(ctx, `select r.capture_run_id from recordings r join capture_runs c on c.id=r.capture_run_id where r.id=$1 and r.project_id=$2 and c.state='active' and r.state in ('open','sealed')`, body.RecordingID, p.ProjectID).Scan(&run); err != nil {
				return httpapi.E(404, "not_found", "unknown recording")
			}
			ok, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: p.ProjectID, Type: body.Type, RecordingID: body.RecordingID, CaptureRunID: run, InputRef: map[string]any{"reprocess": reprocess}, ProcessorVersion: body.ProcessorVersion, Priority: body.Priority})
			if err != nil {
				return err
			}
			if ok {
				created++
			}
		default:
			return httpapi.E(400, "malformed_request", "type must be decode|resolve|transport_audit|coverage|rules")
		}
		_, err := tx.Exec(ctx, `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'job.create',$3,$4,$5)`, p.ProjectID, p.Subject, body.Type, body.RecordingID+body.CaptureRunID, map[string]any{"processor_version": body.ProcessorVersion})
		return err
	})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 202, map[string]any{"created": created})
}

// ---- collectors (read) ----

func (s *Service) ListCollectors(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	items, err := s.list(r.Context(), `select id, name, version, hostname, os, status, capabilities, effective_config, config_version, last_heartbeat_at, health, created_at,
		(select count(*) from collector_requests cr where cr.collector_id=c.id and cr.status in ('pending','delivered')) as pending_requests from collectors c where project_id=$1 order by created_at desc`, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items})
}

func (s *Service) ListCollectorRequests(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	collectorID := r.URL.Query().Get("collector_id")
	if collectorID != "" {
		if _, err := uuid.Parse(collectorID); err != nil {
			httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "collector_id is not a UUID"))
			return
		}
	}
	items, err := s.list(r.Context(), `select * from collector_requests where project_id=$1 and ($2='' or collector_id::text=$2) order by created_at desc limit $3`, p.ProjectID, collectorID, limitParam(r, 100, 1000))
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items})
}

// Overview returns project-level counters for the console home.
func (s *Service) Overview(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	it, err := s.one(r.Context(), `select
		(select count(*) from recordings where project_id=$1) as recordings,
		(select count(*) from recordings where project_id=$1 and state='open') as open_recordings,
		(select count(*) from capture_runs where project_id=$1) as capture_runs,
		(select count(*) from model_attempts where project_id=$1) as attempts,
		(select count(*) from model_inferences where project_id=$1) as inferences,
		(select count(*) from findings where project_id=$1 and status='open') as open_findings,
		(select count(*) from collectors where project_id=$1 and status='online') as online_collectors,
		(select count(*) from processing_jobs where project_id=$1 and status in ('pending','leased')) as active_jobs,
		(select count(*) from processing_jobs where project_id=$1 and status='dead') as dead_jobs,
		(select coalesce(sum(durable_seq - parsed_seq),0) from recordings where project_id=$1) as parse_lag_events`, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, it)
}

// Me returns the caller identity.
func (s *Service) Me(w http.ResponseWriter, r *http.Request) {
	p := httpapi.Principal(r)
	httpapi.WriteJSON(w, 200, map[string]any{"kind": p.Kind, "subject": p.Subject, "role": p.Role, "project_id": p.ProjectID, "tenant_id": p.TenantID})
}

// Events returns a raw event range for evidence links.
func (s *Service) Events(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	id := pathParam(r, "id")
	var owner uuid.UUID
	if err := s.DB.Pool.QueryRow(r.Context(), `select r.project_id from recordings r join capture_runs c on c.id=r.capture_run_id and c.project_id=r.project_id where r.id=$1 and c.state='active' and r.state not in ('deleting','deleted')`, id).Scan(&owner); err != nil || owner != p.ProjectID {
		httpapi.WriteError(w, r, httpapi.E(404, "not_found", "unknown recording"))
		return
	}
	from := int64(1)
	if value := r.URL.Query().Get("from_seq"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 || parsed > (1<<63)-1-200 {
			httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "from_seq is invalid"))
			return
		}
		from = parsed
	}
	to := from + 200
	if value := r.URL.Query().Get("to_seq"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < from || parsed-from > 2000 {
			httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "to_seq is invalid or range exceeds 2000 events"))
			return
		}
		to = parsed
	}
	items, err := s.list(r.Context(), `select e.seq, e.wall_time, e.monotonic_ns, e.source, e.event, e.task_id, e.agent_session_id, e.turn_id, e.inference_id, e.attempt_id, e.connection_id, e.pid, e.payload, e.payload_sha256, e.payload_size, e.redaction from recording_events e join recordings r on r.id=e.recording_id join capture_runs c on c.id=r.capture_run_id and c.project_id=r.project_id where e.recording_id=$1 and r.project_id=$4 and c.state='active' and r.state not in ('deleting','deleted') and e.seq between $2 and $3 order by e.seq`, id, from, to, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if p.Kind == auth.KindUser {
		if _, err := s.DB.Pool.Exec(r.Context(), `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'events.read','recording',$3,$4)`, p.ProjectID, p.Subject, id, map[string]any{"from_seq": from, "to_seq": to}); err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
	}
	httpapi.WriteJSON(w, 200, map[string]any{"items": items})
}
