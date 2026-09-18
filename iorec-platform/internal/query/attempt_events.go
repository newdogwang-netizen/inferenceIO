package query

import (
	"context"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
)

type attemptEventScope struct {
	Project                 uuid.UUID
	Run, Native, Parent, ID string
	Child                   bool
}

type attemptEventPage struct {
	Items        []map[string]any `json:"items"`
	Total        int64            `json:"total"`
	Limit        int              `json:"limit"`
	HasMore      bool             `json:"has_more"`
	NextAfterSeq *int64           `json:"next_after_seq"`
}

const attemptEventFrom = ` from recording_events e join recordings r on r.id=e.recording_id
 left join attempt_event_links l on l.recording_id=e.recording_id and l.seq=e.seq and l.parent_attempt_id=$4 and l.project_id=$2
 where r.capture_run_id=$1 and r.project_id=$2 and e.attempt_id=$3 and (not $5::boolean or l.call_attempt_id=$6)`

func (s *Service) attemptEvents(ctx context.Context, scope attemptEventScope, after int64, limit int, filter string) (attemptEventPage, error) {
	page := attemptEventPage{Items: []map[string]any{}, Limit: limit}
	predicate := ""
	switch filter {
	case "", "all":
	case "unresolved":
		predicate = ` and e.event='websocket_frame' and l.call_attempt_id is null and coalesce(l.reason,'')<>'connection_control'`
	case "control":
		predicate = ` and l.reason='connection_control'`
	case "body":
		predicate = ` and (e.event in ('request_body_chunk','response_body_chunk') or (e.event='websocket_frame' and e.payload->>'opcode'='text'))`
	default:
		return page, httpapi.E(400, "invalid_filter", "filter must be all, body, control, or unresolved")
	}
	args := []any{scope.Run, scope.Project, scope.Native, scope.Parent, scope.Child, scope.ID}
	if err := s.DB.Pool.QueryRow(ctx, `select count(*)`+attemptEventFrom+predicate, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	items, err := s.list(ctx, `select e.recording_id,e.seq,e.wall_time,e.monotonic_ns,e.event,e.task_id,e.agent_session_id,e.payload,e.payload_sha256,e.payload_size,e.raw_media_type,e.raw_truncated,
 l.call_attempt_id,l.reason as assignment_reason,e.payload->>'direction' as direction`+attemptEventFrom+predicate+` and e.seq>$7 order by e.seq,e.recording_id limit $8`, append(args, after, limit+1)...)
	if err != nil {
		return page, err
	}
	if len(items) > limit {
		items = items[:limit]
		page.HasMore = true
		next := items[len(items)-1]["seq"].(int64)
		page.NextAfterSeq = &next
	}
	page.Items = items
	return page, nil
}

func eventCursor(r *http.Request) (int64, error) {
	if raw := r.URL.Query().Get("after_seq"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return 0, httpapi.E(400, "invalid_cursor", "after_seq must be a non-negative integer")
		}
		return n, nil
	}
	return 0, nil
}

// GetAttemptEvents offers bounded, cursor-based evidence reads. Cursor sequence
// numbers are run-global; recording IDs are still returned for exact references.
func (s *Service) GetAttemptEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	idx := pathParam(r, "id")
	a, err := s.one(r.Context(), `select a.id,a.capture_run_id,a.native_id,a.entity_kind,a.parent_attempt_id,p.native_id as parent_native
 from model_attempts a join capture_runs c on c.id=a.capture_run_id and c.project_id=a.project_id
 join recordings rec on rec.id=a.recording_id and rec.project_id=a.project_id
 left join model_attempts p on p.id=a.parent_attempt_id and p.project_id=a.project_id
 where a.id=$1 and a.project_id=$2 and c.state='active' and rec.state not in ('deleting','deleted')`, idx, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	scope := attemptEventScope{Project: p.ProjectID, ID: idx, Parent: idx, Run: a["capture_run_id"].(string), Native: a["native_id"].(string)}
	if a["entity_kind"] == "websocket_call" {
		scope.Child = true
		scope.Parent, _ = a["parent_attempt_id"].(string)
		scope.Native, _ = a["parent_native"].(string)
	}
	after, err := eventCursor(r)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	page, err := s.attemptEvents(r.Context(), scope, after, limitParam(r, 200, 1000), r.URL.Query().Get("filter"))
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if p.Kind == auth.KindUser {
		if _, err := s.DB.Pool.Exec(r.Context(), `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'attempt.events.read','attempt',$3,$4)`, p.ProjectID, p.Subject, idx, map[string]any{"after_seq": after, "count": len(page.Items), "filter": r.URL.Query().Get("filter")}); err != nil {
			httpapi.WriteError(w, r, err)
			return
		}
	}
	httpapi.WriteJSON(w, 200, page)
}
