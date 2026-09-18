package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// wsMessage retains the immutable event address even when its body is missing.
// A gap disables implicit association; explicit response IDs remain useful.
type wsMessage struct {
	Event   rawEvent
	Meta    websocketFrameMetadata
	Body    []byte
	Problem string
}

type wsAssignment struct {
	Call   int // -1 means connection-level or unresolved evidence, never silently dropped
	Reason string
}

type wsCall struct {
	Request         int
	Frames          []int
	ResponseID      string
	RequestID       string
	Association     string
	Outcome         string
	CancelRequested bool
	Problems        []string
	Norm            *Normalized
	Response        json.RawMessage
}

type wsProjection struct {
	Calls       []*wsCall
	Assignments []wsAssignment
	Unresolved  int
}

func wsString(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

func wsObject(obj map[string]any, key string) map[string]any {
	m, _ := obj[key].(map[string]any)
	return m
}

// splitWebSocketCalls is a conservative Responses-over-WebSocket state machine.
// It never treats the connection's transport outcome as a model outcome. In
// particular, a completed response cannot complete another pending request.
// Frames without an unambiguous owner stay individually enumerable.
func splitWebSocketCalls(apiMode string, frames []wsMessage, closed bool) wsProjection {
	p := wsProjection{Assignments: make([]wsAssignment, len(frames))}
	requests, responses, items := map[string]int{}, map[string]int{}, map[string]int{}
	pending, active, orphanResponses := map[int]bool{}, map[int]bool{}, map[string]bool{}
	implicitSafe := true
	assign := func(frame, call int, reason string) {
		p.Assignments[frame] = wsAssignment{call, reason}
		if call >= 0 {
			p.Calls[call].Frames = append(p.Calls[call].Frames, frame)
		}
	}
	unique := func(candidates map[int]bool) int {
		if len(candidates) != 1 {
			return -1
		}
		for c := range candidates {
			return c
		}
		return -1
	}
	for i, f := range frames {
		assign(i, -1, "unresolved_protocol_event")
		if f.Problem != "" {
			implicitSafe = false
			assign(i, -1, f.Problem)
			// A gap before an otherwise valid message must not erase a visible
			// response.create. It only removes the right to infer its pairing.
			if f.Problem != "sequence_gap" || len(f.Body) == 0 {
				continue
			}
		}
		if f.Meta.Opcode != "text" {
			switch f.Meta.Opcode {
			case "ping", "pong", "close":
				assign(i, -1, "connection_control")
			default:
				implicitSafe = false
				assign(i, -1, "unsupported_opcode")
			}
			continue
		}
		var obj map[string]any
		if !utf8.Valid(f.Body) || json.Unmarshal(f.Body, &obj) != nil || obj == nil {
			implicitSafe = false
			assign(i, -1, "invalid_json")
			continue
		}
		typ := wsString(obj, "type")
		if apiMode != "responses" && apiMode != "codex_responses" {
			assign(i, -1, "unsupported_websocket_api")
			continue
		}
		if f.Meta.Direction == "client_to_upstream" && typ == "response.create" {
			body := f.Body
			if nested := wsObject(obj, "response"); nested != nil {
				body, _ = json.Marshal(nested)
			}
			n, err := NormalizeRequest(apiMode, body)
			c := &wsCall{Request: i, RequestID: wsString(obj, "event_id"), Association: "pending", Outcome: "unknown", Norm: n}
			if err != nil {
				c.Norm = &Normalized{APIMode: apiMode, BodyUnavailable: true}
				c.Problems = append(c.Problems, "invalid_request")
			}
			index := len(p.Calls)
			p.Calls = append(p.Calls, c)
			pending[index] = true
			if c.RequestID != "" {
				if old, exists := requests[c.RequestID]; exists {
					requests[c.RequestID] = -1
					c.Problems = append(c.Problems, "duplicate_request_id")
					if old >= 0 {
						p.Calls[old].Problems = append(p.Calls[old].Problems, "duplicate_request_id")
					}
				} else {
					requests[c.RequestID] = index
				}
			}
			assign(i, index, "request")
			continue
		}
		rid := wsString(obj, "response_id")
		if nested := wsObject(obj, "response"); nested != nil {
			if id := wsString(nested, "id"); id != "" {
				if rid != "" && rid != id {
					implicitSafe = false
					assign(i, -1, "conflicting_response_ids")
					continue
				}
				rid = id
			}
		}
		if f.Meta.Direction == "client_to_upstream" {
			if typ == "response.cancel" {
				owner := -1
				if rid != "" {
					if x, ok := responses[rid]; ok && active[x] {
						owner = x
					}
				} else if implicitSafe && len(pending) == 0 && len(orphanResponses) == 0 {
					owner = unique(active)
				}
				if owner >= 0 {
					p.Calls[owner].CancelRequested = true
					assign(i, owner, "cancel_requested")
				} else {
					assign(i, -1, "unresolved_cancel")
				}
			} else {
				implicitSafe = false
				assign(i, -1, "unsupported_client_event")
			}
			continue
		}
		if f.Meta.Direction != "upstream_to_client" {
			implicitSafe = false
			assign(i, -1, "invalid_direction")
			continue
		}
		if typ == "response.created" {
			if rid == "" {
				implicitSafe = false
				assign(i, -1, "missing_response_id")
				continue
			}
			if old, exists := responses[rid]; exists {
				if old >= 0 {
					p.Calls[old].Problems = append(p.Calls[old].Problems, "duplicate_response_id")
				}
				responses[rid] = -1
				orphanResponses[rid] = true
				implicitSafe = false
				assign(i, -1, "duplicate_response_id")
				continue
			}
			owner, method := -1, "unique_pending_request"
			requestID := wsString(obj, "request_id")
			if requestID == "" {
				requestID = wsString(wsObject(obj, "response"), "request_id")
			}
			if requestID != "" {
				if x, ok := requests[requestID]; ok && pending[x] {
					owner = x
					method = "explicit_request_id"
				}
			} else if implicitSafe && len(orphanResponses) == 0 {
				owner = unique(pending)
			}
			responses[rid] = owner
			if owner < 0 {
				orphanResponses[rid] = true
				assign(i, -1, "ambiguous_response_created")
				continue
			}
			delete(pending, owner)
			active[owner] = true
			c := p.Calls[owner]
			c.ResponseID = rid
			c.Association = method
			assign(i, owner, method)
			continue
		}
		owner, method := -1, "explicit_response_id"
		if rid != "" {
			if x, ok := responses[rid]; ok && active[x] {
				owner = x
			}
		} else if typ == "error" {
			requestID := wsString(wsObject(obj, "error"), "event_id")
			if requestID != "" {
				if x, ok := requests[requestID]; ok && (active[x] || pending[x]) {
					owner = x
					method = "explicit_request_id"
				}
			} else if implicitSafe && len(orphanResponses) == 0 {
				candidates := map[int]bool{}
				for x := range pending {
					candidates[x] = true
				}
				for x := range active {
					candidates[x] = true
				}
				owner = unique(candidates)
				method = "unique_outstanding_error"
			}
		} else if strings.HasPrefix(typ, "response.") {
			itemID := wsString(obj, "item_id")
			if itemID == "" {
				itemID = wsString(wsObject(obj, "item"), "id")
			}
			if x, ok := items[itemID]; itemID != "" && ok {
				if active[x] {
					owner = x
					method = "explicit_item_id"
				}
			} else if implicitSafe && len(pending) == 0 && len(orphanResponses) == 0 {
				owner = unique(active)
				method = "unique_active_response"
			}
		}
		terminal := typ == "response.completed" || typ == "response.failed" || typ == "response.incomplete" || typ == "response.cancelled" || typ == "error"
		if owner < 0 {
			assign(i, -1, "unresolved_response")
			if terminal && rid != "" {
				delete(orphanResponses, rid)
			}
			continue
		}
		assign(i, owner, method)
		if typ == "response.output_item.added" || typ == "response.output_item.done" {
			itemID := wsString(wsObject(obj, "item"), "id")
			if itemID != "" {
				if old, ok := items[itemID]; ok && old != owner {
					items[itemID] = -1
					p.Calls[owner].Problems = append(p.Calls[owner].Problems, "duplicate_item_id")
				} else {
					items[itemID] = owner
				}
			}
		}
		if terminal {
			c := p.Calls[owner]
			c.Outcome = strings.TrimPrefix(typ, "response.")
			if typ == "error" {
				c.Outcome = "failed"
			}
			if c.Association == "pending" {
				c.Association = method
			}
			if response := wsObject(obj, "response"); response != nil {
				c.Response, _ = json.Marshal(response)
				if status := wsString(response, "status"); status != "" && status != c.Outcome {
					c.Outcome = "conflicting"
					c.Problems = append(c.Problems, "conflicting_terminal_status")
				}
			}
			delete(active, owner)
			delete(pending, owner)
		}
	}
	for _, a := range p.Assignments {
		if a.Call < 0 && a.Reason != "connection_control" {
			p.Unresolved++
		}
	}
	for _, c := range p.Calls {
		if c.Association == "pending" {
			c.Association = "unresolved"
		}
		if c.Outcome == "unknown" {
			if closed {
				c.Problems = append(c.Problems, "missing_model_terminal")
			} else {
				c.Outcome = "in_progress"
			}
		}
		var chunks []string
		for _, idx := range c.Frames {
			if frames[idx].Meta.Direction == "upstream_to_client" {
				chunks = append(chunks, "data: "+string(frames[idx].Body)+"\n\n")
			}
		}
		ApplyStream(c.Norm, chunks)
		c.Norm.ResponseID = c.ResponseID
		// A final output snapshot replaces, rather than duplicates, streamed text
		// and tool calls. Usage is the provider's final snapshot, never a sum.
		if len(c.Response) > 0 {
			var final map[string]any
			_ = json.Unmarshal(c.Response, &final)
			if _, hasOutput := final["output"]; hasOutput {
				c.Norm.ResponseText = ""
				c.Norm.ResponseToolCalls = nil
			}
			ApplyResponseBody(c.Norm, c.Response)
		}
		if c.Outcome == "failed" || c.Outcome == "cancelled" {
			c.Norm.FinishReason = c.Outcome
			done := true
			c.Norm.StreamTerminated = &done
		}
		if c.Outcome == "conflicting" {
			c.Norm.FinishReason = "conflicting_terminal_status"
		}
		c.Norm.finalize()
	}
	return p
}

func wsCallKey(parent string, seq int64) string {
	return fmt.Sprintf("wscall:%d:%s:%d", len(parent), parent, seq)
}
