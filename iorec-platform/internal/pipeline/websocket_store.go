package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/protocol"
	"github.com/jackc/pgx/v5"
)

type wsCapture struct {
	Frames         []wsMessage
	Closed         bool
	Complete       bool // proxy-message integrity, not a wire-coverage claim
	Problems       []string
	Terminal       string
	CloseDiagnosis string
	ErrorDetail    json.RawMessage
}

func (d *Deps) loadWebSocketCapture(ctx context.Context, project, run, native string) (wsCapture, error) {
	events, err := d.loadRunEvents(ctx, run, `and e.attempt_id=$2 and e.event in ('websocket_frame','websocket_connection_finished')`, native)
	if err != nil {
		return wsCapture{}, err
	}
	c := wsCapture{Complete: true, CloseDiagnosis: "not_observed"}
	expected := map[string]int64{"client_to_upstream": 1, "upstream_to_client": 1}
	counts := map[string]int64{}
	var finish *websocketFinishMetadata
	total := 0
	for _, e := range events {
		if e.Event == protocol.EvWebSocketFinished {
			if finish != nil {
				c.Complete = false
				c.Problems = append(c.Problems, "multiple_connection_terminals")
			}
			var f websocketFinishMetadata
			if json.Unmarshal(e.Payload, &f) != nil {
				c.Complete = false
				c.Problems = append(c.Problems, "invalid_connection_terminal")
				continue
			}
			finish = &f
			c.Closed = true
			c.Terminal = terminalState(e.TerminalState)
			c.CloseDiagnosis = "unspecified_connection_end"
			c.ErrorDetail = f.ErrorDetail
			var detail struct {
				ProtocolKind string `json:"protocol_kind"`
			}
			if json.Unmarshal(f.ErrorDetail, &detail) == nil && detail.ProtocolKind == "reset_without_closing_handshake" {
				c.CloseDiagnosis = "unclean_close"
			}
			if f.Reason == "client_close" || f.Reason == "upstream_close" {
				c.CloseDiagnosis = "close_frame_observed"
			}
			continue
		}
		f := wsMessage{Event: e}
		if json.Unmarshal(e.Payload, &f.Meta) != nil {
			f.Problem = "invalid_frame_metadata"
		}
		next, known := expected[f.Meta.Direction]
		if !known {
			f.Problem = "invalid_direction"
		} else {
			if f.Meta.MessageSequence != next {
				f.Problem = "sequence_gap"
			}
			expected[f.Meta.Direction] = f.Meta.MessageSequence + 1
			counts[f.Meta.Direction]++
		}
		if c.Closed {
			f.Problem = "frame_after_connection_terminal"
		}
		if f.Meta.ObservedSize < 0 || f.Meta.CapturedSize != f.Meta.ObservedSize || e.RawTruncated {
			f.Problem = "truncated_frame"
		}
		digest := strings.TrimPrefix(strings.ToLower(f.Meta.SHA256), "sha256:")
		if f.Meta.CapturedSize == 0 {
			empty := sha256.Sum256(nil)
			if digest != "" && digest != hex.EncodeToString(empty[:]) {
				f.Problem = "invalid_empty_digest"
			}
		} else if len(e.PayloadSHA) == 0 || e.PayloadSize == nil || *e.PayloadSize != f.Meta.CapturedSize || digest != hex.EncodeToString(e.PayloadSHA) {
			f.Problem = "invalid_payload_reference"
		} else if total >= 64<<20 {
			f.Problem = "processing_byte_limit"
		} else {
			body, available, err := d.bodyBytes(ctx, project, nil, e.PayloadSHA)
			if err != nil {
				return c, err
			}
			if !available || int64(len(body)) != f.Meta.CapturedSize {
				f.Problem = "missing_body"
			} else if len(body) > (64<<20)-total {
				f.Problem = "processing_byte_limit"
			} else {
				f.Body = body
				total += len(body)
			}
		}
		if f.Problem != "" {
			c.Complete = false
			c.Problems = appendUnique(c.Problems, f.Problem)
		}
		c.Frames = append(c.Frames, f)
	}
	if finish == nil {
		c.Complete = false
		c.Problems = append(c.Problems, "connection_terminal_not_observed")
	} else {
		if finish.CaptureFailed {
			c.Complete = false
			c.Problems = append(c.Problems, "capture_failed")
		}
		if finish.ClientMessages != counts["client_to_upstream"] || finish.UpstreamMessages != counts["upstream_to_client"] {
			c.Complete = false
			c.Problems = append(c.Problems, "terminal_message_count_mismatch")
		}
	}
	return c, nil
}

func wsEvidence(frames []wsMessage, indices []int) []EvidenceRef {
	refs := make([]EvidenceRef, 0)
	for _, i := range indices {
		e := frames[i].Event
		if len(refs) > 0 && refs[len(refs)-1].RecordingID == e.RecordingID && refs[len(refs)-1].LastSeq+1 == e.Seq {
			refs[len(refs)-1].LastSeq = e.Seq
		} else {
			refs = append(refs, EvidenceRef{e.RecordingID, e.Seq, e.Seq})
		}
	}
	return refs
}

func wsAttemptTerminal(outcome string) string {
	switch outcome {
	case "completed":
		return "completed"
	case "failed":
		return "error"
	case "cancelled":
		return "cancelled"
	case "incomplete":
		return "truncated"
	default:
		return "unknown"
	}
}

// Normalize a complete connection snapshot atomically. The parent row lock
// prevents older concurrent snapshots from replacing a newer call projection.
func (d *Deps) normalizeWebSocketCalls(ctx context.Context, j *jobs.Job, run, id, native, apiMode string) error {
	return d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var parentKind string
		var previous json.RawMessage
		if err := tx.QueryRow(ctx, `select entity_kind,projection from model_attempts where id=$1 and project_id=$2 for update`, id, j.ProjectID).Scan(&parentKind, &previous); err != nil {
			return err
		}
		if parentKind == "websocket_call" {
			return nil
		}
		// A long connection can occur in many batches. Verify its immutable
		// bodies once per snapshot/generation, not once per touched batch.
		type snapshot struct {
			Count      int64  `json:"count"`
			LastSeq    int64  `json:"last_seq"`
			Generation string `json:"generation"`
			Version    string `json:"version"`
		}
		var input batchRef
		_ = json.Unmarshal(j.InputRef, &input)
		current := snapshot{Generation: input.Reprocess, Version: NormalizerVersion}
		if err := tx.QueryRow(ctx, `select count(*),coalesce(max(e.seq),0) from recording_events e join recordings r on r.id=e.recording_id where r.capture_run_id=$1 and r.project_id=$2 and e.attempt_id=$3 and e.event in ('websocket_frame','websocket_connection_finished')`, run, j.ProjectID, native).Scan(&current.Count, &current.LastSeq); err != nil {
			return err
		}
		var old struct {
			Snapshot     snapshot `json:"evidence_snapshot"`
			CaptureState string   `json:"capture_state"`
		}
		if json.Unmarshal(previous, &old) == nil && old.CaptureState == "observed_messages_verified" && old.Snapshot == current {
			// Assembly can refresh transport fields after semantic projection.
			_, err := tx.Exec(ctx, `update model_attempts set inference_id=null,processor_version=$2 where id=$1`, id, NormalizerVersion)
			return err
		}
		capture, err := d.loadWebSocketCapture(ctx, j.ProjectID.String(), run, native)
		if err != nil {
			return err
		}
		projection := splitWebSocketCalls(apiMode, capture.Frames, capture.Closed)
		captureState := "incomplete"
		if capture.Complete {
			captureState = "observed_messages_verified"
		}
		if !capture.Closed {
			captureState = "open"
		}
		callIDs := make([]string, 0, len(projection.Calls))
		for _, call := range projection.Calls {
			request := capture.Frames[call.Request]
			callID := wsCallKey(id, request.Event.Seq)
			callIDs = append(callIDs, callID)
			last := capture.Frames[call.Frames[len(call.Frames)-1]].Event
			var ended any
			if call.Outcome != "unknown" && call.Outcome != "in_progress" {
				ended = last.WallTime
			}
			var firstByte any
			for _, index := range call.Frames {
				if capture.Frames[index].Meta.Direction == "upstream_to_client" {
					firstByte = capture.Frames[index].Event.WallTime
					break
				}
			}
			if !capture.Complete {
				call.Norm.BodyUnavailable = true
			}
			normalized, _ := json.Marshal(call.Norm)
			usage, _ := json.Marshal(call.Norm.Usage)
			requestBody, requestNUL, err := postgresJSON(request.Body)
			if err != nil {
				return fmt.Errorf("sanitize WebSocket request projection: %w", err)
			}
			responseBody, responseNUL, err := postgresJSON(call.Response)
			if err != nil {
				return fmt.Errorf("sanitize WebSocket response projection: %w", err)
			}
			normalized, normalizedNUL, err := postgresJSON(normalized)
			if err != nil {
				return fmt.Errorf("sanitize normalized WebSocket projection: %w", err)
			}
			usage, usageNUL, err := postgresJSON(usage)
			if err != nil {
				return fmt.Errorf("sanitize WebSocket usage projection: %w", err)
			}
			responseText, responseTextNUL := postgresText(truncateStr(call.Norm.ResponseText, 200000))
			model, modelNUL := postgresText(call.Norm.Model)
			responseID, responseIDNUL := postgresText(call.ResponseID)
			requestID, requestIDNUL := postgresText(call.RequestID)
			problemNUL := 0
			for index := range call.Problems {
				var count int
				call.Problems[index], count = postgresText(call.Problems[index])
				problemNUL += count
			}
			nulReplacements := requestNUL + responseNUL + normalizedNUL + usageNUL + responseTextNUL + modelNUL + responseIDNUL + requestIDNUL + problemNUL
			if nulReplacements > 0 {
				call.Problems = appendUnique(call.Problems, "postgres_nul_replaced_in_projection")
			}
			refs, _ := json.Marshal(wsEvidence(capture.Frames, call.Frames))
			meta, _ := json.Marshal(map[string]any{"schema_version": 1, "kind": "websocket_call", "outcome": call.Outcome, "association": call.Association, "response_id": responseID, "request_event_id": requestID, "cancel_requested": call.CancelRequested, "issues": call.Problems, "capture_state": captureState, "capture_scope": "parent_connection_observed_messages", "message_count": len(call.Frames), "postgres_nul_replacements": nulReplacements})
			fp, _ := hex.DecodeString(call.Norm.Fingerprint)
			ih, _ := hex.DecodeString(call.Norm.InputHash)
			_, err = tx.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,connection_id,task_id,session_id,source,protocol,method,url,provider_host,api_mode,model,started_at,ended_at,first_byte_at,terminal_state,request_body,request_body_ref,response_body,response_text,usage,normalized,request_fingerprint,input_hash,first_seq,last_seq,processor_version,pid,container_id,entity_kind,parent_attempt_id,projection,evidence_refs)
			select $1,$1,$3,project_id,capture_run_id,connection_id,task_id,session_id,'proxy:websocket-call','websocket_message','MESSAGE',url,provider_host,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,pid,container_id,'websocket_call',id,$21,$22 from model_attempts where id=$2
			on conflict(id) do update set recording_id=excluded.recording_id,api_mode=excluded.api_mode,model=excluded.model,started_at=excluded.started_at,ended_at=excluded.ended_at,first_byte_at=excluded.first_byte_at,terminal_state=excluded.terminal_state,request_body=excluded.request_body,request_body_ref=excluded.request_body_ref,response_body=excluded.response_body,response_text=excluded.response_text,usage=excluded.usage,normalized=excluded.normalized,request_fingerprint=excluded.request_fingerprint,input_hash=excluded.input_hash,first_seq=excluded.first_seq,last_seq=excluded.last_seq,processor_version=excluded.processor_version,projection=excluded.projection,evidence_refs=excluded.evidence_refs,updated_at=now()`,
				callID, id, request.Event.RecordingID, apiMode, nilIfEmpty(model), request.Event.WallTime, ended, firstByte, wsAttemptTerminal(call.Outcome), requestBody, request.Event.PayloadSHA, nullJSON(responseBody), nilIfEmpty(responseText), usage, normalized, fp, ih, request.Event.Seq, last.Seq, NormalizerVersion, meta, refs)
			if err != nil {
				return fmt.Errorf("persist WebSocket call: %w", err)
			}
		}
		if _, err = tx.Exec(ctx, `delete from attempt_event_links where parent_attempt_id=$1`, id); err != nil {
			return err
		}
		rows := make([][]any, 0, len(capture.Frames))
		for index, f := range capture.Frames {
			a := projection.Assignments[index]
			var owner any
			if a.Call >= 0 {
				owner = callIDs[a.Call]
			}
			rows = append(rows, []any{j.ProjectID, id, f.Event.RecordingID, f.Event.Seq, owner, a.Reason, NormalizerVersion})
		}
		if _, err = tx.CopyFrom(ctx, pgx.Identifier{"attempt_event_links"}, []string{"project_id", "parent_attempt_id", "recording_id", "seq", "call_attempt_id", "reason", "processor_version"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `delete from model_attempts where parent_attempt_id=$1 and not(id=any($2::text[]))`, id, callIDs); err != nil {
			return err
		}
		summary, _ := json.Marshal(map[string]any{"schema_version": 1, "kind": "websocket_connection", "calls": len(callIDs), "message_count": len(capture.Frames), "unresolved_messages": projection.Unresolved, "capture_state": captureState, "capture_scope": "observed_proxy_messages_not_wire_coverage", "issues": capture.Problems, "close_diagnosis": capture.CloseDiagnosis, "error_detail": capture.ErrorDetail, "evidence_snapshot": current})
		// A connection is never itself a model call. Remove the old aggregate
		// response/usage/hash projection rather than leaving misleading totals.
		_, err = tx.Exec(ctx, `update model_attempts set entity_kind='websocket_connection',inference_id=null,normalized=null,response_text=null,usage=null,request_fingerprint=null,input_hash=null,projection=$2,processor_version=$3,updated_at=now() where id=$1`, id, summary, NormalizerVersion)
		return err
	})
}
