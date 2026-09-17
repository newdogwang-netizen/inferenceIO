package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/protocol"
)

// rawEvent is a row of recording_events.
type rawEvent struct {
	RecordingID   string
	Seq           int64
	MonotonicNS   int64
	WallTime      time.Time
	Source        string
	Event         string
	IDs           protocol.IDs
	Payload       json.RawMessage
	PayloadSHA    []byte
	PayloadSize   *int64
	RawMediaType  string
	RawTruncated  bool
	TerminalState string
}

const maxEventsPerEntity = 100_000

func (d *Deps) loadEvents(ctx context.Context, rec, where string, args ...any) ([]rawEvent, error) {
	q := `select recording_id, seq, monotonic_ns, wall_time, source, event, coalesce(task_id,''), coalesce(agent_session_id,''), coalesce(turn_id,''), coalesce(inference_id,''), coalesce(attempt_id,''), coalesce(connection_id,''), coalesce(parent_span_id,''), coalesce(pid,0), coalesce(container_id,''), payload, payload_sha256, payload_size, coalesce(raw_media_type,''), raw_truncated, coalesce(terminal_state,'')
		from recording_events where recording_id=$1 ` + where + ` order by seq limit 100001`
	rows, err := d.DB.Pool.Query(ctx, q, append([]any{rec}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rawEvent
	for rows.Next() {
		var e rawEvent
		if err := rows.Scan(&e.RecordingID, &e.Seq, &e.MonotonicNS, &e.WallTime, &e.Source, &e.Event, &e.IDs.TaskID, &e.IDs.AgentSessionID, &e.IDs.TurnID, &e.IDs.InferenceID, &e.IDs.AttemptID, &e.IDs.ConnectionID, &e.IDs.ParentSpanID, &e.IDs.PID, &e.IDs.ContainerID, &e.Payload, &e.PayloadSHA, &e.PayloadSize, &e.RawMediaType, &e.RawTruncated, &e.TerminalState); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) > maxEventsPerEntity {
		return nil, fmt.Errorf("entity event count exceeds processing limit %d", maxEventsPerEntity)
	}
	return out, rows.Err()
}

func (d *Deps) loadRunEvents(ctx context.Context, run, where string, args ...any) ([]rawEvent, error) {
	q := `select e.recording_id, e.seq, e.monotonic_ns, e.wall_time, e.source, e.event, coalesce(e.task_id,''), coalesce(e.agent_session_id,''), coalesce(e.turn_id,''), coalesce(e.inference_id,''), coalesce(e.attempt_id,''), coalesce(e.connection_id,''), coalesce(e.parent_span_id,''), coalesce(e.pid,0), coalesce(e.container_id,''), e.payload, e.payload_sha256, e.payload_size, coalesce(e.raw_media_type,''), e.raw_truncated, coalesce(e.terminal_state,'')
		from recording_events e join recordings r on r.id=e.recording_id where r.capture_run_id=$1 ` + where + ` order by e.seq, e.recording_id limit 100001`
	rows, err := d.DB.Pool.Query(ctx, q, append([]any{run}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rawEvent
	for rows.Next() {
		var e rawEvent
		if err := rows.Scan(&e.RecordingID, &e.Seq, &e.MonotonicNS, &e.WallTime, &e.Source, &e.Event, &e.IDs.TaskID, &e.IDs.AgentSessionID, &e.IDs.TurnID, &e.IDs.InferenceID, &e.IDs.AttemptID, &e.IDs.ConnectionID, &e.IDs.ParentSpanID, &e.IDs.PID, &e.IDs.ContainerID, &e.Payload, &e.PayloadSHA, &e.PayloadSize, &e.RawMediaType, &e.RawTruncated, &e.TerminalState); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) > maxEventsPerEntity {
		return nil, fmt.Errorf("run-scoped entity event count exceeds processing limit %d", maxEventsPerEntity)
	}
	return out, rows.Err()
}

// Assemble builds ModelAttempt rows (and hook-observed ModelInference rows) for
// every attempt/inference touched by the batch.
func (d *Deps) Assemble(ctx context.Context, j *jobs.Job) error {
	br, err := d.batchRef(j)
	if err != nil {
		return err
	}
	rec := *j.RecordingID
	run := runIDOf(j)
	rows, err := d.DB.Pool.Query(ctx, `select distinct attempt_id from recording_events where recording_id=$1 and seq between $2 and $3 and attempt_id is not null`, rec, br.FirstSeq, br.LastSeq)
	if err != nil {
		return err
	}
	var attemptIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		attemptIDs = append(attemptIDs, id)
	}
	rows.Close()
	for _, id := range attemptIDs {
		evs, err := d.loadRunEvents(ctx, run, `and e.attempt_id=$2`, id)
		if err != nil {
			return err
		}
		if err := d.upsertAttempt(ctx, j, rec, run, id, evs); err != nil {
			return fmt.Errorf("attempt %s: %w", id, err)
		}
	}
	// hook-observed inferences
	rows, err = d.DB.Pool.Query(ctx, `select distinct inference_id from recording_events where recording_id=$1 and seq between $2 and $3 and inference_id is not null and event in ('inference_request','inference_response','inference_error','logical_inference_request','pre_api_request','post_api_request','api_request_error')`, rec, br.FirstSeq, br.LastSeq)
	if err != nil {
		return err
	}
	var infIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		infIDs = append(infIDs, id)
	}
	rows.Close()
	for _, id := range infIDs {
		evs, err := d.loadRunEvents(ctx, run, `and e.inference_id=$2 and e.event in ('inference_request','inference_response','inference_error','logical_inference_request','pre_api_request','post_api_request','api_request_error')`, id)
		if err != nil {
			return err
		}
		if err := d.upsertObservedInference(ctx, j, rec, run, id, evs); err != nil {
			return fmt.Errorf("inference %s: %w", id, err)
		}
	}
	return d.enqueueNext(ctx, j.ProjectID, jobs.TypeNormalize, rec, run, br, NormalizerVersion, 8)
}

type attemptStart struct {
	Method   string          `json:"method"`
	URL      string          `json:"url"`
	URI      json.RawMessage `json:"uri"`
	Upstream json.RawMessage `json:"upstream"`
	Host     string          `json:"host"`
	Protocol string          `json:"protocol"`
	APIMode  string          `json:"api_mode"`
	Model    string          `json:"model"`
	Headers  json.RawMessage `json:"headers"`
}

type hookAPIEvent struct {
	Model           string          `json:"model"`
	APIMode         string          `json:"api_mode"`
	BaseURL         string          `json:"base_url"`
	Request         json.RawMessage `json:"request"`
	RequestMessages json.RawMessage `json:"request_messages"`
	Response        json.RawMessage `json:"response"`
	Usage           json.RawMessage `json:"usage"`
	StatusCode      *int            `json:"status_code"`
	Error           struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// hookRequestBody preserves the directly observed request when available. A
// Hermes hook may instead send only a bounded preview plus a compact message
// list. In that case the synthetic body remains useful for normalization but
// carries an explicit marker so it can never be mistaken for a complete wire
// request.
func hookRequestBody(p hookAPIEvent) json.RawMessage {
	if len(p.Request) > 0 {
		var wrapper map[string]any
		if json.Unmarshal(p.Request, &wrapper) == nil && wrapper["preview"] == nil {
			return p.Request
		}
	}
	if len(p.RequestMessages) == 0 {
		return nil
	}
	var messages any
	if json.Unmarshal(p.RequestMessages, &messages) != nil {
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"model":                   p.Model,
		"messages":                messages,
		"_iorec_body_unavailable": true,
	})
	return body
}

func (d *Deps) upsertAttempt(ctx context.Context, j *jobs.Job, rec, run, id string, evs []rawEvent) error {
	if len(evs) == 0 {
		return nil
	}
	rec = evs[0].RecordingID
	var (
		st                        attemptStart
		reqHeaders, respHeaders   json.RawMessage
		reqBody, respBody         json.RawMessage
		reqRef, respRef           []byte
		status                    *int
		terminal                  = "unknown"
		errClass                  *string
		sseCount                  int
		started, ended, firstByte *time.Time
		connection, taskID        string
		sessionID, source         string
		pid                       *int
		container                 *string
		reqChunks, respChunks     int
	)
	source = evs[0].Source
	for _, e := range evs {
		if err := mergeStableIdentity(&taskID, e.IDs.TaskID, "task"); err != nil {
			return err
		}
		if err := mergeStableIdentity(&sessionID, e.IDs.AgentSessionID, "session"); err != nil {
			return err
		}
		if e.IDs.ConnectionID != "" {
			connection = e.IDs.ConnectionID
		}
		if e.IDs.PID != 0 {
			p := e.IDs.PID
			pid = &p
		}
		if e.IDs.ContainerID != "" {
			c := e.IDs.ContainerID
			container = &c
		}
		switch e.Event {
		case protocol.EvAttemptStart, protocol.EvTransportRequestStarted:
			_ = json.Unmarshal(e.Payload, &st)
			if st.URL == "" {
				st.URL = endpointText(st.Upstream)
			}
			if st.URL == "" {
				st.URL = endpointText(st.URI)
			}
			if len(st.Headers) > 0 {
				reqHeaders = st.Headers
			}
			t := e.WallTime
			started = &t
		case protocol.EvRequestHeaders:
			var p struct {
				Headers json.RawMessage `json:"headers"`
			}
			if json.Unmarshal(e.Payload, &p) == nil && len(p.Headers) > 0 {
				reqHeaders = p.Headers
			} else {
				reqHeaders = e.Payload
			}
			if started == nil {
				t := e.WallTime
				started = &t
			}
		case protocol.EvRequestBody:
			if len(e.Payload) > 0 {
				reqBody = e.Payload
			}
			if e.PayloadSHA != nil {
				reqRef = e.PayloadSHA
			}
		case protocol.EvRequestBodyChunk:
			reqChunks++
			if reqChunks == 1 && !e.RawTruncated {
				reqRef = e.PayloadSHA
			} else {
				reqRef = nil
			}
		case protocol.EvResponseHeaders, protocol.EvTransportResponseStarted:
			var p struct {
				Status  int             `json:"status"`
				Headers json.RawMessage `json:"headers"`
			}
			if json.Unmarshal(e.Payload, &p) == nil {
				if p.Status != 0 {
					s := p.Status
					status = &s
				}
				respHeaders = p.Headers
			}
			t := e.WallTime
			firstByte = &t
		case protocol.EvSSEChunk, protocol.EvSSEEvent:
			sseCount++
			if firstByte == nil {
				t := e.WallTime
				firstByte = &t
			}
		case protocol.EvResponseBody:
			if len(e.Payload) > 0 {
				respBody = e.Payload
			}
			if e.PayloadSHA != nil {
				respRef = e.PayloadSHA
			}
		case protocol.EvResponseBodyChunk:
			respChunks++
			if respChunks == 1 && !e.RawTruncated {
				respRef = e.PayloadSHA
			} else {
				respRef = nil
			}
		case protocol.EvAttemptEnd, protocol.EvTransportAttemptFinished:
			var p struct {
				Reason    string `json:"reason"`
				Status    *int   `json:"status"`
				ErrorKind string `json:"error_kind"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			terminal = terminalState(e.TerminalState)
			if terminal == "unknown" {
				terminal = "completed"
			}
			if p.Reason == "truncated" {
				terminal = "truncated"
			}
			if p.Status != nil && status == nil {
				status = p.Status
			}
			if terminal == "error" {
				class := p.ErrorKind
				if class == "" {
					class = "error"
				}
				errClass = &class
			}
			t := e.WallTime
			ended = &t
		case protocol.EvAttemptError:
			var p struct {
				Class   string `json:"class"`
				Message string `json:"message"`
				Status  *int   `json:"status"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			terminal = "error"
			c := p.Class
			if c == "" {
				c = "error"
			}
			errClass = &c
			if p.Status != nil && status == nil {
				status = p.Status
			}
			t := e.WallTime
			ended = &t
		case protocol.EvAttemptCancel:
			terminal = "cancelled"
			t := e.WallTime
			ended = &t
		case "pre_api_request":
			var p hookAPIEvent
			_ = json.Unmarshal(e.Payload, &p)
			st.Method = "POST"
			st.URL = p.BaseURL
			st.APIMode = p.APIMode
			st.Model = p.Model
			if body := hookRequestBody(p); len(body) > 0 {
				reqBody = body
			}
			if started == nil {
				t := e.WallTime
				started = &t
			}
		case "post_api_request":
			var p hookAPIEvent
			_ = json.Unmarshal(e.Payload, &p)
			if len(p.Response) > 0 {
				respBody = p.Response
			}
			terminal = "completed"
			t := e.WallTime
			ended = &t
		case "api_request_error":
			var p hookAPIEvent
			_ = json.Unmarshal(e.Payload, &p)
			terminal = "error"
			if p.StatusCode != nil {
				status = p.StatusCode
			}
			class := p.Error.Type
			if class == "" {
				class = "error"
			}
			errClass = &class
			// The complete hook payload contains the structured error and is
			// normalized by ApplyResponseBody's generic error handling.
			respBody = e.Payload
			t := e.WallTime
			ended = &t
		}
	}
	if status != nil && *status >= 400 && terminal == "completed" {
		terminal = "error"
		c := fmt.Sprintf("http_%d", *status)
		errClass = &c
	}
	if started == nil {
		t := evs[0].WallTime
		started = &t
	}
	host := st.Host
	if host == "" && st.URL != "" {
		if u, err := url.Parse(st.URL); err == nil {
			host = u.Host
		}
	}
	apiMode := st.APIMode
	if apiMode == "" {
		apiMode = detectAPIMode(st.URL)
	}
	var explicitInference *string
	for _, e := range evs {
		if e.IDs.InferenceID != "" {
			v := InferenceKey(run, e.IDs.InferenceID)
			explicitInference = &v
			break
		}
	}
	_, err := d.DB.Pool.Exec(ctx, `insert into model_attempts(id, recording_id, project_id, capture_run_id, inference_id, connection_id, task_id, session_id, source, protocol, method, url, provider_host, api_mode,
			started_at, ended_at, first_byte_at, terminal_state, status_code, error_class, request_headers, response_headers, request_body, request_body_ref, response_body, response_body_ref,
			sse_event_count, first_seq, last_seq, processor_version, pid, container_id, updated_at, native_id)
		values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,now(),$33)
		on conflict (id) do update set recording_id=excluded.recording_id, inference_id=coalesce(excluded.inference_id, model_attempts.inference_id), connection_id=excluded.connection_id, task_id=coalesce(excluded.task_id,model_attempts.task_id), session_id=coalesce(excluded.session_id,model_attempts.session_id), protocol=excluded.protocol, method=excluded.method, url=excluded.url, provider_host=excluded.provider_host,
			api_mode=coalesce(nullif(excluded.api_mode,'unknown'), model_attempts.api_mode), started_at=excluded.started_at, ended_at=excluded.ended_at, first_byte_at=excluded.first_byte_at, terminal_state=excluded.terminal_state,
			status_code=excluded.status_code, error_class=excluded.error_class, request_headers=excluded.request_headers, response_headers=excluded.response_headers,
			request_body=excluded.request_body, request_body_ref=excluded.request_body_ref, response_body=excluded.response_body, response_body_ref=excluded.response_body_ref,
			sse_event_count=excluded.sse_event_count, first_seq=excluded.first_seq, last_seq=excluded.last_seq, processor_version=excluded.processor_version, pid=excluded.pid, container_id=excluded.container_id, updated_at=now()`,
		AttemptKey(run, id), rec, j.ProjectID, run, explicitInference, nilIfEmpty(connection), nilIfEmpty(taskID), nilIfEmpty(sessionID), source, nilIfEmpty(st.Protocol), nilIfEmpty(st.Method), nilIfEmpty(st.URL), nilIfEmpty(host), apiMode,
		started, ended, firstByte, terminal, status, errClass, nullJSON(reqHeaders), nullJSON(respHeaders), nullJSON(reqBody), reqRef, nullJSON(respBody), respRef,
		sseCount, evs[0].Seq, evs[len(evs)-1].Seq, AssemblerVersion, pid, container, id)
	if err == nil && st.Model != "" {
		_, err = d.DB.Pool.Exec(ctx, `update model_attempts set model=coalesce(nullif($2,''),model) where id=$1`, AttemptKey(run, id), st.Model)
	}
	return err
}

func nullJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func terminalState(value string) string {
	switch value {
	case "complete":
		return "completed"
	case "error":
		return "error"
	case "cancelled":
		return "cancelled"
	case "incomplete":
		return "truncated"
	default:
		return "unknown"
	}
}

func endpointText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var endpoint struct {
		Scheme string `json:"scheme"`
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Path   string `json:"path"`
	}
	if json.Unmarshal(raw, &endpoint) != nil {
		return ""
	}
	if endpoint.Host == "" {
		return endpoint.Path
	}
	authority := endpoint.Host
	if endpoint.Port > 0 {
		authority = fmt.Sprintf("%s:%d", authority, endpoint.Port)
	}
	if endpoint.Scheme == "" {
		return authority + endpoint.Path
	}
	return endpoint.Scheme + "://" + authority + endpoint.Path
}

func (d *Deps) upsertObservedInference(ctx context.Context, j *jobs.Job, rec, run, id string, evs []rawEvent) error {
	if len(evs) == 0 {
		return nil
	}
	rec = evs[0].RecordingID
	var req, resp, usage json.RawMessage
	var model, apiMode, taskID, sessionID, turnID string
	var first *time.Time
	var pid *int
	for _, e := range evs {
		if err := mergeStableIdentity(&taskID, e.IDs.TaskID, "task"); err != nil {
			return err
		}
		if err := mergeStableIdentity(&sessionID, e.IDs.AgentSessionID, "session"); err != nil {
			return err
		}
		if e.IDs.TurnID != "" {
			turnID = e.IDs.TurnID
		}
		if e.IDs.PID != 0 {
			p := e.IDs.PID
			pid = &p
		}
		switch e.Event {
		case protocol.EvInferenceRequest:
			var p struct {
				Model   string          `json:"model"`
				APIMode string          `json:"api_mode"`
				Request json.RawMessage `json:"request"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			model, apiMode, req = p.Model, p.APIMode, p.Request
			if first == nil {
				t := e.WallTime
				first = &t
			}
		case "logical_inference_request":
			var p struct {
				Path    string `json:"path"`
				Summary struct {
					Model string `json:"model"`
				} `json:"summary"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			model = p.Summary.Model
			apiMode = detectAPIMode(p.Path)
			if first == nil {
				t := e.WallTime
				first = &t
			}
		case "pre_api_request":
			var p hookAPIEvent
			_ = json.Unmarshal(e.Payload, &p)
			model, apiMode, req = p.Model, p.APIMode, hookRequestBody(p)
			if first == nil {
				t := e.WallTime
				first = &t
			}
		case protocol.EvInferenceResp:
			var p struct {
				Response json.RawMessage `json:"response"`
				Usage    json.RawMessage `json:"usage"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			resp, usage = p.Response, p.Usage
		case "post_api_request":
			var p struct {
				Response json.RawMessage `json:"response"`
				Usage    json.RawMessage `json:"usage"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			resp, usage = p.Response, p.Usage
		case protocol.EvInferenceError:
			resp = e.Payload
		case "api_request_error":
			resp = e.Payload
		}
	}
	if first == nil {
		t := evs[0].WallTime
		first = &t
	}
	if apiMode == "" {
		apiMode = "unknown"
	}
	ev, _ := json.Marshal(eventEvidenceRefs(evs))
	_, err := d.DB.Pool.Exec(ctx, `insert into model_inferences(id, recording_id, capture_run_id, project_id, status, first_attempt_at, model, api_mode, request, response, usage, task_id, session_id, turn_id, pid, evidence_refs, processor_version, native_id)
		values($1,$2,$3,$4,'observed',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		on conflict (id) do update set recording_id=excluded.recording_id, status='observed', first_attempt_at=excluded.first_attempt_at, model=coalesce(excluded.model, model_inferences.model), api_mode=excluded.api_mode, request=coalesce(excluded.request, model_inferences.request),
			response=coalesce(excluded.response, model_inferences.response), usage=coalesce(excluded.usage, model_inferences.usage), task_id=coalesce(excluded.task_id, model_inferences.task_id), session_id=coalesce(excluded.session_id, model_inferences.session_id), turn_id=coalesce(excluded.turn_id, model_inferences.turn_id),
			pid=coalesce(excluded.pid, model_inferences.pid), evidence_refs=excluded.evidence_refs, updated_at=now()`,
		InferenceKey(run, id), rec, run, j.ProjectID, first, nilIfEmpty(model), apiMode, nullJSON(req), nullJSON(resp), nullJSON(usage), nilIfEmpty(taskID), nilIfEmpty(sessionID), nilIfEmpty(turnID), pid, ev, AssemblerVersion, id)
	return err
}

func mergeStableIdentity(current *string, observed, kind string) error {
	if observed == "" {
		return nil
	}
	if *current == "" {
		*current = observed
		return nil
	}
	if *current != observed {
		return fmt.Errorf("%s ID is inconsistent across entity evidence", kind)
	}
	return nil
}

func eventEvidenceRefs(evs []rawEvent) []EvidenceRef {
	var refs []EvidenceRef
	for _, event := range evs {
		if len(refs) == 0 || refs[len(refs)-1].RecordingID != event.RecordingID {
			refs = append(refs, EvidenceRef{RecordingID: event.RecordingID, FirstSeq: event.Seq, LastSeq: event.Seq})
			continue
		}
		refs[len(refs)-1].LastSeq = event.Seq
	}
	return refs
}

// detectAPIMode infers the provider API family from the URL path.
func detectAPIMode(u string) string {
	p := strings.ToLower(u)
	switch {
	case strings.Contains(p, "/chat/completions"):
		return "chat_completions"
	case strings.Contains(p, "/v1/messages"):
		return "anthropic_messages"
	case strings.Contains(p, ":generatecontent"), strings.Contains(p, ":streamgeneratecontent"):
		return "gemini_generate"
	case strings.Contains(p, "/responses"):
		return "responses"
	case strings.Contains(p, "/completions"):
		return "completions"
	case strings.Contains(p, "/embeddings"):
		return "embeddings"
	}
	return "unknown"
}
