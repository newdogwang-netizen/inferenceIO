package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/pipeline"
)

// One predicate for both summary and progress. Hook observations, discovery
// requests and physical WS parents must never inflate model-call totals.
const modelCallPredicate = `((a.source='proxy' and a.entity_kind='request') or
 (a.source='proxy:websocket-call' and a.entity_kind='websocket_call')) and
 a.api_mode in ('chat_completions','completions','responses','codex_responses','anthropic_messages','gemini_generate')`

const progressMaxCalls = 5000
const progressMaxBytes = 64 << 20
const progressMaxResponseBytes = 8 << 20
const progressPreviewRunes = 1200

type progressInput struct {
	ID, RecordingID, InferenceID, SessionID, ParentID string
	NativeSession                                     bool
	Model, APIMode, Terminal                          string
	FirstSeq, LastSeq                                 int64
	StartedAt, EndedAt                                *time.Time
	Normalized                                        pipeline.Normalized
}

type progressEvidence struct {
	AttemptID   string `json:"attempt_id"`
	RecordingID string `json:"recording_id"`
	FirstSeq    int64  `json:"first_seq"`
	LastSeq     int64  `json:"last_seq"`
}

type progressResult struct {
	Evidence    progressEvidence `json:"evidence"`
	CallOrdinal int              `json:"call_ordinal"`
	Preview     string           `json:"preview"`
	Characters  int              `json:"characters"`
	SHA256      string           `json:"sha256"`
}

type progressTool struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	ArgumentsPreview    string           `json:"arguments_preview"`
	ArgumentsCharacters int              `json:"arguments_characters"`
	ArgumentsAvailable  bool             `json:"arguments_available"`
	ArgumentsHash       string           `json:"arguments_hash,omitempty"`
	State               string           `json:"state"`
	Evidence            progressEvidence `json:"evidence"`
	Result              *progressResult  `json:"result,omitempty"`
	ResultVariants      int              `json:"result_variants"`
	ObservationCount    int              `json:"observation_count"`
	Candidates          []string         `json:"ambiguous_consumers,omitempty"`
	resultHashes        map[string]bool
}

type progressLink struct {
	AttemptID string `json:"attempt_id"`
	Ordinal   int    `json:"ordinal,omitempty"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
}

type progressCall struct {
	Ordinal        int              `json:"ordinal"`
	Evidence       progressEvidence `json:"evidence"`
	InferenceID    string           `json:"inference_id,omitempty"`
	SessionID      string           `json:"session_id,omitempty"`
	ParentID       string           `json:"parent_connection_id,omitempty"`
	Model          string           `json:"model"`
	APIMode        string           `json:"api_mode"`
	Terminal       string           `json:"terminal_state"`
	StartedAt      *time.Time       `json:"started_at"`
	EndedAt        *time.Time       `json:"ended_at"`
	InputPreview   string           `json:"input_preview"`
	Response       string           `json:"response_preview"`
	ResponseChars  int              `json:"response_characters"`
	Usage          map[string]any   `json:"usage,omitempty"`
	Tools          []*progressTool  `json:"tools"`
	Predecessors   []progressLink   `json:"predecessors"`
	UnmatchedTools int              `json:"unmatched_tool_results"`
	BodyMissing    bool             `json:"body_unavailable"`
}

type progressToolSummary struct {
	Requested        int `json:"requested"`
	ResultsObserved  int `json:"results_observed"`
	AwaitingEvidence int `json:"awaiting_result_evidence"`
	Ambiguous        int `json:"ambiguous"`
	Conflicting      int `json:"conflicting"`
	UnmatchedResults int `json:"unmatched_result_observations"`
}

func preview(s string) string {
	if utf8.RuneCountInString(s) <= progressPreviewRunes {
		return s
	}
	return string([]rune(s)[:progressPreviewRunes]) + "…"
}

func progressRef(a progressInput) progressEvidence {
	return progressEvidence{a.ID, a.RecordingID, a.FirstSeq, a.LastSeq}
}

func progressPrecedes(a, b progressInput) bool {
	return a.FirstSeq > 0 && b.FirstSeq > a.FirstSeq &&
		(!a.NativeSession || !b.NativeSession || a.SessionID == b.SessionID)
}

// Bound structural work as well as bytes: a small JSON body can contain many
// duplicate IDs, otherwise making producer/result matching quadratic.
func progressWithinWorkBudget(input []progressInput) bool {
	producers := map[string]int{}
	toolCount, messageCount, comparisons := 0, 0, 0
	for _, a := range input {
		toolCount += len(a.Normalized.ResponseToolCalls)
		messageCount += len(a.Normalized.Messages)
		if toolCount > 10000 || messageCount > 100000 {
			return false
		}
		for _, t := range a.Normalized.ResponseToolCalls {
			if t.ID != "" {
				producers[t.ID]++
			}
		}
	}
	for _, a := range input {
		for _, m := range a.Normalized.Messages {
			if m.Role == "tool" {
				comparisons += producers[m.ToolCallID]
			}
			if comparisons > 1000000 {
				return false
			}
		}
	}
	return true
}

// buildProgress never equates model intent with execution success. It links
// returned tool results only by a unique explicit ID, within a compatible
// session, and only after an observed producer. Repeated context is evidence of
// the same result, not additional tool executions. Conflicts stay visible.
func buildProgress(input []progressInput) ([]progressCall, progressToolSummary) {
	calls := make([]progressCall, 0, len(input))
	producers := map[string][]struct{ call, tool int }{}
	responses := map[string][]int{}
	for i, a := range input {
		c := progressCall{Ordinal: i + 1, Evidence: progressRef(a), InferenceID: a.InferenceID,
			SessionID: a.SessionID, ParentID: a.ParentID, Model: a.Model, APIMode: a.APIMode,
			Terminal: a.Terminal, StartedAt: a.StartedAt, EndedAt: a.EndedAt,
			Response: preview(a.Normalized.ResponseText), ResponseChars: utf8.RuneCountInString(a.Normalized.ResponseText),
			Usage: a.Normalized.Usage, Tools: []*progressTool{}, Predecessors: []progressLink{}, BodyMissing: a.Normalized.BodyUnavailable}
		for _, m := range a.Normalized.Messages {
			if m.Role == "user" && c.InputPreview == "" {
				c.InputPreview = preview(m.Text)
			}
		}
		seen := map[string]bool{}
		for j, t := range a.Normalized.ResponseToolCalls {
			arg := ""
			if t.Arguments != nil {
				if s, ok := t.Arguments.(string); ok {
					arg = s
				} else if b, err := json.Marshal(t.Arguments); err == nil {
					arg = string(b)
				}
			}
			keyBytes, _ := json.Marshal([]string{t.ID, t.Name, t.ArgsHash, arg})
			key := string(keyBytes)
			if t.ID != "" && seen[key] {
				continue
			}
			seen[key] = true
			id := t.ID
			state := "requested_only"
			if id == "" {
				id, state = fmt.Sprintf("unidentified:%s:%d", a.ID, j), "missing_call_id"
			}
			tool := &progressTool{ID: id, Name: t.Name, ArgumentsPreview: preview(arg), ArgumentsCharacters: utf8.RuneCountInString(arg),
				ArgumentsAvailable: t.Arguments != nil, ArgumentsHash: t.ArgsHash, State: state, Evidence: progressRef(a), resultHashes: map[string]bool{}}
			if t.ID != "" {
				producers[t.ID] = append(producers[t.ID], struct{ call, tool int }{i, len(c.Tools)})
			}
			c.Tools = append(c.Tools, tool)
		}
		if id := a.Normalized.ResponseID; id != "" {
			responses[id] = append(responses[id], i)
		}
		calls = append(calls, c)
	}
	for i, a := range input {
		links := map[string]bool{}
		link := func(j int, kind string) {
			key := input[j].ID + "/" + kind
			if !links[key] {
				calls[i].Predecessors = append(calls[i].Predecessors, progressLink{AttemptID: input[j].ID, Ordinal: j + 1, Kind: kind, Status: "explicit_id"})
				links[key] = true
			}
		}
		if id := a.Normalized.PreviousResponseID; id != "" {
			matches := []int{}
			for _, j := range responses[id] {
				if j < i && progressPrecedes(input[j], a) {
					matches = append(matches, j)
				}
			}
			if len(matches) == 1 {
				link(matches[0], "previous_response_id")
			} else {
				calls[i].Predecessors = append(calls[i].Predecessors, progressLink{Kind: "previous_response_id", Status: "unresolved"})
			}
		}
		for _, m := range a.Normalized.Messages {
			if m.Role != "tool" {
				continue
			}
			matches := [][2]int{}
			for _, p := range producers[m.ToolCallID] {
				if p.call < i && progressPrecedes(input[p.call], a) {
					matches = append(matches, [2]int{p.call, p.tool})
				}
			}
			if len(matches) != 1 {
				calls[i].UnmatchedTools++
				for _, p := range matches {
					t := calls[p[0]].Tools[p[1]]
					t.State = "ambiguous_call_id"
					t.Candidates = append(t.Candidates, a.ID)
				}
				continue
			}
			p := matches[0]
			t := calls[p[0]].Tools[p[1]]
			h := sha256.Sum256([]byte(m.Text))
			digest := hex.EncodeToString(h[:])
			t.ObservationCount++
			t.resultHashes[digest] = true
			t.ResultVariants = len(t.resultHashes)
			if t.Result == nil {
				t.Result = &progressResult{Evidence: progressRef(a), CallOrdinal: i + 1, Preview: preview(m.Text), Characters: utf8.RuneCountInString(m.Text), SHA256: digest}
				link(p[0], "tool_call_id")
			}
			if t.State != "ambiguous_call_id" {
				t.State = "result_observed"
				if t.ResultVariants > 1 {
					t.State = "conflicting_results"
				}
			}
		}
	}
	var summary progressToolSummary
	for _, c := range calls {
		summary.UnmatchedResults += c.UnmatchedTools
		for _, t := range c.Tools {
			summary.Requested++
			switch t.State {
			case "result_observed":
				summary.ResultsObserved++
			case "conflicting_results":
				summary.Conflicting++
			case "ambiguous_call_id", "missing_call_id":
				summary.Ambiguous++
			default:
				summary.AwaitingEvidence++
			}
		}
	}
	return calls, summary
}

// GetProgress is a task/run scoped read model, not a rewrite of original
// evidence. Repeatable-read keeps summary and graph on one database snapshot.
// Explicit resource ceilings fail closed instead of silently dropping steps.
func (s *Service) GetProgress(w http.ResponseWriter, r *http.Request) {
	p, ok := requireViewer(w, r)
	if !ok {
		return
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 || v > progressMaxCalls {
			httpapi.WriteError(w, r, httpapi.E(400, "invalid_cursor", "invalid progress offset"))
			return
		}
		offset = v
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tx, err := s.DB.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	fail := func(err error) { httpapi.WriteError(w, r, err) }
	var run string
	var revision int64
	var benchmark json.RawMessage
	err = tx.QueryRow(ctx, `select c.id,c.analysis_revision,c.benchmark_result from recordings r
 join capture_runs c on c.id=r.capture_run_id and c.project_id=r.project_id
 where r.id=$1 and r.project_id=$2 and c.state='active' and r.state not in ('deleting','deleted','expired','expiring')`, pathParam(r, "id"), p.ProjectID).Scan(&run, &revision, &benchmark)
	if err == pgx.ErrNoRows {
		fail(httpapi.E(404, "not_found", "unknown active recording"))
		return
	}
	if err != nil {
		fail(err)
		return
	}
	var attempts, modelCalls, connections, hooks, other int64
	err = tx.QueryRow(ctx, `select count(*),count(*) filter(where `+modelCallPredicate+`),
 count(*) filter(where a.entity_kind='websocket_connection'),count(*) filter(where a.source like 'hook:%'),
 count(*) filter(where a.source='proxy' and a.entity_kind='request' and not (`+modelCallPredicate+`))
 from model_attempts a join recordings r on r.id=a.recording_id and r.project_id=a.project_id
 where a.capture_run_id=$1 and a.project_id=$2 and r.state not in ('deleting','deleted','expired','expiring')`, run, p.ProjectID).Scan(&attempts, &modelCalls, &connections, &hooks, &other)
	if err != nil {
		fail(err)
		return
	}
	if modelCalls > progressMaxCalls {
		fail(httpapi.E(413, "progress_limit", "progress projection exceeds 5000 model calls; original evidence remains available"))
		return
	}
	var rawEvents, sseEvents, wsMessages, hookEvents, eventWatermark int64
	err = tx.QueryRow(ctx, `select count(*),count(*) filter(where e.event='sse_event'),
 count(*) filter(where e.event='websocket_frame'),count(*) filter(where e.source like 'hook:%'),coalesce(max(e.seq),0)
 from recording_events e join recordings r on r.id=e.recording_id
 where r.capture_run_id=$1 and r.project_id=$2 and r.state not in ('deleting','deleted','expired','expiring')`, run, p.ProjectID).
		Scan(&rawEvents, &sseEvents, &wsMessages, &hookEvents, &eventWatermark)
	if err != nil {
		fail(err)
		return
	}
	rows, err := tx.Query(ctx, `select a.id,a.recording_id,coalesce(a.inference_id,''),coalesce(a.session_id,''),coalesce(a.parent_attempt_id,''),coalesce(s.kind='native',false),
 coalesce(a.model,''),coalesce(a.api_mode,''),a.terminal_state,coalesce(a.first_seq,0),coalesce(a.last_seq,0),a.started_at,a.ended_at,
 coalesce(octet_length(a.normalized::text),0),case when octet_length(a.normalized::text)<=8388608 then a.normalized end
 from model_attempts a join recordings r on r.id=a.recording_id and r.project_id=a.project_id
 left join sessions s on s.id=a.session_id and s.project_id=a.project_id and not s.superseded
 where a.capture_run_id=$1 and a.project_id=$2 and r.state not in ('deleting','deleted','expired','expiring') and (`+modelCallPredicate+`)
 order by a.first_seq nulls last,a.started_at nulls last,a.id`, run, p.ProjectID)
	if err != nil {
		fail(err)
		return
	}
	inputs := []progressInput{}
	bytesRead := 0
	missingNormalized := 0
	for rows.Next() {
		var a progressInput
		var norm json.RawMessage
		var size int
		if err = rows.Scan(&a.ID, &a.RecordingID, &a.InferenceID, &a.SessionID, &a.ParentID, &a.NativeSession, &a.Model, &a.APIMode, &a.Terminal,
			&a.FirstSeq, &a.LastSeq, &a.StartedAt, &a.EndedAt, &size, &norm); err != nil {
			break
		}
		bytesRead += size
		if bytesRead > progressMaxBytes || size > 8<<20 {
			err = httpapi.E(413, "progress_limit", "progress normalization exceeds bounded read size; original evidence remains available")
			break
		}
		if len(norm) == 0 || string(norm) == "null" {
			a.Normalized.BodyUnavailable = true
			missingNormalized++
		} else if err = json.Unmarshal(norm, &a.Normalized); err != nil {
			err = httpapi.E(409, "progress_normalization_invalid", "normalized model evidence requires reprocessing")
			break
		}
		inputs = append(inputs, a)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		fail(err)
		return
	}
	if !progressWithinWorkBudget(inputs) {
		fail(httpapi.E(413, "progress_limit", "progress tool graph exceeds bounded work size; original evidence remains available"))
		return
	}
	calls, tools := buildProgress(inputs)
	limit := limitParam(r, 25, 100)
	if offset > len(calls) {
		offset = len(calls)
	}
	end := min(offset+limit, len(calls))
	var next *int
	if end < len(calls) {
		next = &end
	}
	// Evidence-dependent key makes clients reset pagination when a live task or
	// reprocessing changes the snapshot, instead of joining incompatible pages.
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s/%d/%d/%d/%d/%d/%d/%d", run, revision, eventWatermark, rawEvents, attempts, hooks, connections, other)
	_, _ = h.Write(benchmark)
	for _, a := range inputs {
		b, _ := json.Marshal(a)
		_, _ = h.Write(b)
	}
	snapshot := hex.EncodeToString(h.Sum(nil))
	if want := r.URL.Query().Get("snapshot"); want != "" && !strings.EqualFold(want, snapshot) {
		fail(httpapi.E(409, "progress_snapshot_changed", "task evidence changed; restart progress pagination"))
		return
	}
	body := map[string]any{
		"schema_version": 1, "capture_run_id": run, "scope": "capture_run_all_available_segments", "snapshot": snapshot,
		"summary": map[string]any{"model_calls": modelCalls, "websocket_connections": connections, "hook_observations": hooks,
			"other_http_requests": other, "all_attempt_rows": attempts, "raw_events": rawEvents, "sse_events": sseEvents,
			"websocket_messages": wsMessages, "stream_events": sseEvents + wsMessages, "hook_events": hookEvents, "tools": tools,
			"normalization_pending": missingNormalized},
		"items": calls[offset:end], "total": len(calls), "offset": offset, "limit": limit, "next_offset": next,
		"benchmark_result": benchmark,
		"limits": []string{"Model requests are not human conversation rounds; retries remain separate requests.",
			"Connections count observed WebSocket parents, not inferred HTTP keep-alive sockets.",
			"Tool result observation does not assert command success, exact execution time or terminal exit status.",
			"Chronological order is not a causal edge; only explicit unique IDs produce predecessor links.",
			"Hook observations are separate; repeated model context is not another tool execution."},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		fail(err)
		return
	}
	if len(encoded) > progressMaxResponseBytes {
		fail(httpapi.E(413, "progress_limit", "progress page exceeds 8 MiB; request a smaller page or inspect original evidence"))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail(err)
		return
	}
	if _, err := s.DB.Pool.Exec(ctx, `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail)
 values($1,$2,'recording.progress.read','capture_run',$3,$4)`, p.ProjectID, p.Subject, run,
		map[string]any{"snapshot": snapshot, "offset": offset, "count": end - offset}); err != nil {
		fail(err)
		return
	}
	httpapi.WriteJSON(w, 200, json.RawMessage(encoded))
}
