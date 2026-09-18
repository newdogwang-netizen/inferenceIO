package pipeline

import (
	"encoding/json"
	"reflect"
	"testing"
)

func wsFixture(messages ...string) []wsMessage {
	var out []wsMessage
	for i, m := range messages {
		direction := "upstream_to_client"
		if len(m) > 0 && m[0] == '>' {
			direction = "client_to_upstream"
			m = m[1:]
		}
		out = append(out, wsMessage{Event: rawEvent{RecordingID: "test#0000", Seq: int64(i + 1)}, Meta: websocketFrameMetadata{Direction: direction, Opcode: "text"}, Body: []byte(m)})
	}
	return out
}

func TestWSCallsSeparateOutcomesAndFinalSnapshots(t *testing.T) {
	frames := wsFixture(
		`>{"type":"response.create","model":"m","input":"first"}`,
		`{"type":"response.created","response":{"id":"r1"}}`,
		`{"type":"response.output_text.delta","delta":"answer"}`,
		`{"type":"response.output_item.done","item":{"type":"function_call","id":"i1","call_id":"tool1","name":"shell","arguments":"{}"}}`,
		`{"type":"response.completed","response":{"id":"r1","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"answer"}]},{"type":"function_call","call_id":"tool1","name":"shell","arguments":"{}"}],"usage":{"input_tokens":10,"output_tokens":5}}}`,
		`>{"type":"response.create","model":"m","previous_response_id":"r1","input":"second"}`,
		`{"type":"response.created","response":{"id":"r2"}}`,
		`{"type":"response.output_text.delta","delta":"partial"}`,
	)
	p := splitWebSocketCalls("responses", frames, true)
	if len(p.Calls) != 2 || p.Unresolved != 0 {
		t.Fatalf("projection: %+v", p)
	}
	a, b := p.Calls[0], p.Calls[1]
	if a.Outcome != "completed" || b.Outcome != "unknown" || b.Norm.ResponseText != "partial" {
		t.Fatalf("outcomes %s/%s, partial %q", a.Outcome, b.Outcome, b.Norm.ResponseText)
	}
	if a.Norm.ResponseText != "answer" || len(a.Norm.ResponseToolCalls) != 1 || a.Norm.Usage["output_tokens"] != float64(5) {
		t.Fatalf("double counted final: %+v", a.Norm)
	}
	if b.Norm.PreviousResponseID != "r1" || b.Norm.Usage != nil {
		t.Fatal("cross-call state or usage contamination")
	}
	if !reflect.DeepEqual(p, splitWebSocketCalls("responses", frames, true)) {
		t.Fatal("non-deterministic projection")
	}
}

func TestWSCallsInterleavingRequiresExplicitAssociation(t *testing.T) {
	frames := wsFixture(
		`>{"type":"response.create","event_id":"q1","input":"one"}`,
		`>{"type":"response.create","event_id":"q2","input":"two"}`,
		`{"type":"response.created","request_id":"q2","response":{"id":"r2"}}`,
		`{"type":"response.created","request_id":"q1","response":{"id":"r1"}}`,
		`{"type":"response.output_text.delta","delta":"ambiguous"}`,
		`{"type":"response.output_item.added","response_id":"r2","item":{"id":"i2"}}`,
		`{"type":"response.output_text.delta","item_id":"i2","delta":"two"}`,
		`{"type":"response.failed","response":{"id":"r1","status":"failed"}}`,
		`{"type":"response.completed","response":{"id":"r2","status":"completed"}}`,
	)
	p := splitWebSocketCalls("responses", frames, true)
	if p.Unresolved != 1 || p.Assignments[4].Call != -1 || p.Assignments[6].Call != 1 || p.Calls[0].Outcome != "failed" || p.Calls[1].Norm.ResponseText != "two" {
		t.Fatalf("incorrect pairing: %+v", p)
	}
}

func TestWSCallsAmbiguousCreatedDoesNotGuessFIFO(t *testing.T) {
	p := splitWebSocketCalls("responses", wsFixture(
		`>{"type":"response.create","input":"one"}`,
		`>{"type":"response.create","input":"two"}`,
		`{"type":"response.created","response":{"id":"r1"}}`,
		`{"type":"response.completed","response":{"id":"r1","status":"completed"}}`,
	), true)
	if p.Unresolved != 2 {
		t.Fatalf("unresolved %d", p.Unresolved)
	}
	for _, c := range p.Calls {
		if c.Outcome != "unknown" || c.Association != "unresolved" {
			t.Fatal("guessed concurrent call")
		}
	}
}

func TestWSCallsCancelIsIntentUntilConfirmed(t *testing.T) {
	base := wsFixture(`>{"type":"response.create","input":"one"}`, `{"type":"response.created","response":{"id":"r1"}}`, `>{"type":"response.cancel","response_id":"r1"}`)
	p := splitWebSocketCalls("responses", base, true)
	if !p.Calls[0].CancelRequested || p.Calls[0].Outcome != "unknown" {
		t.Fatal("cancel request is not confirmed cancellation")
	}
	base = append(base, wsFixture(`{"type":"response.cancelled","response":{"id":"r1","status":"cancelled"}}`)[0])
	p = splitWebSocketCalls("responses", base, true)
	if p.Calls[0].Outcome != "cancelled" || !*p.Calls[0].Norm.StreamTerminated {
		t.Fatal("cancel outcome missing")
	}
}

func TestWSCallsErrorsAndGapsFailClosed(t *testing.T) {
	t.Run("explicit error", func(t *testing.T) {
		p := splitWebSocketCalls("responses", wsFixture(`>{"type":"response.create","event_id":"q","input":"one"}`, `{"type":"error","error":{"event_id":"q","code":"bad_request"}}`), true)
		if p.Calls[0].Outcome != "failed" || p.Unresolved != 0 {
			t.Fatal("failed to associate explicit error")
		}
	})
	t.Run("gap", func(t *testing.T) {
		f := wsFixture(`>{"type":"response.create","input":"one"}`, `{}`, `{"type":"response.created","response":{"id":"r1"}}`, `{"type":"response.completed","response":{"id":"r1","status":"completed"}}`)
		f[1].Problem = "missing_body"
		p := splitWebSocketCalls("responses", f, true)
		if p.Unresolved != 3 || p.Calls[0].Outcome != "unknown" {
			t.Fatal("gap allowed implicit pairing")
		}
	})
	t.Run("explicit after gap", func(t *testing.T) {
		f := wsFixture(`>{"type":"response.create","event_id":"q","input":"one"}`, `{}`, `{"type":"response.created","request_id":"q","response":{"id":"r1"}}`, `{"type":"response.completed","response":{"id":"r1","status":"completed"}}`)
		f[1].Problem = "sequence_gap"
		p := splitWebSocketCalls("responses", f, true)
		if p.Unresolved != 1 || p.Calls[0].Outcome != "completed" {
			t.Fatal("explicit evidence lost after gap")
		}
	})
}

func TestWSCallsKeepControlAndUnknownEvents(t *testing.T) {
	f := wsFixture(`>{"type":"response.create","input":"one"}`, `{}`, `{"type":"future.event"}`)
	f[1].Meta.Opcode = "ping"
	p := splitWebSocketCalls("responses", f, false)
	if len(p.Assignments) != 3 || p.Unresolved != 1 || p.Assignments[1].Reason != "connection_control" || p.Calls[0].Outcome != "in_progress" {
		t.Fatalf("lost evidence %+v", p)
	}
	b, _ := json.Marshal(p)
	if !json.Valid(b) {
		t.Fatal("invalid projection")
	}
}

func TestWSCallKeySeparatesConnectionsAndRequests(t *testing.T) {
	if wsCallKey("a:1", 2) == wsCallKey("a", 12) || wsCallKey("a", 1) == wsCallKey("b", 1) {
		t.Fatal("key collision")
	}
}

func TestWSCallsLateItemCannotContaminateNextResponse(t *testing.T) {
	p := splitWebSocketCalls("responses", wsFixture(
		`>{"type":"response.create","input":"one"}`,
		`{"type":"response.created","response":{"id":"r1"}}`,
		`{"type":"response.output_item.added","item":{"id":"old-item"}}`,
		`{"type":"response.completed","response":{"id":"r1","status":"completed"}}`,
		`>{"type":"response.create","input":"two"}`,
		`{"type":"response.created","response":{"id":"r2"}}`,
		`{"type":"response.output_text.delta","item_id":"old-item","delta":"wrong"}`,
	), true)
	if p.Unresolved != 1 || p.Assignments[6].Call != -1 || p.Calls[1].Norm.ResponseText != "" {
		t.Fatal("late item assigned to next response")
	}
}

func TestWSCallsVisibleRequestSurvivesSequenceGap(t *testing.T) {
	f := wsFixture(`>{"type":"response.create","input":"visible"}`, `{"type":"response.created","response":{"id":"r1"}}`)
	f[0].Problem = "sequence_gap"
	p := splitWebSocketCalls("responses", f, true)
	if len(p.Calls) != 1 || p.Calls[0].Norm.Messages[0].Text != "visible" || p.Calls[0].Association != "unresolved" {
		t.Fatal("gap erased visible request or invented association")
	}
}

func TestWSCallsConflictingTerminalIsNotSuccessful(t *testing.T) {
	p := splitWebSocketCalls("responses", wsFixture(`>{"type":"response.create","input":"one"}`, `{"type":"response.created","response":{"id":"r1"}}`, `{"type":"response.completed","response":{"id":"r1","status":"failed"}}`), true)
	if p.Calls[0].Outcome != "conflicting" || wsAttemptTerminal(p.Calls[0].Outcome) != "unknown" || p.Calls[0].Norm.FinishReason != "conflicting_terminal_status" {
		t.Fatal("contradictory terminal falsely successful")
	}
}

func TestWSCallsCustomToolsAndResults(t *testing.T) {
	p := splitWebSocketCalls("responses", wsFixture(
		`>{"type":"response.create","input":[{"type":"additional_tools","tools":[{"type":"namespace","name":"functions","tools":[{"type":"custom","name":"exec"}]}]},{"type":"message","role":"user","content":"run"}]}`,
		`{"type":"response.created","response":{"id":"r1"}}`,
		`{"type":"response.output_item.done","item":{"type":"custom_tool_call","call_id":"c1","name":"exec","input":"ls"}}`,
		`{"type":"response.completed","response":{"id":"r1","status":"completed","output":[{"type":"custom_tool_call","call_id":"c1","name":"exec","input":"ls"}]}}`,
		`>{"type":"response.create","previous_response_id":"r1","input":[{"type":"custom_tool_call_output","call_id":"c1","output":"files"},{"type":"reasoning","encrypted_content":"opaque"}]}`,
	), true)
	a, b := p.Calls[0].Norm, p.Calls[1].Norm
	if len(a.Messages) != 1 || len(a.Tools) != 1 || a.Tools[0] != "functions.exec" || len(a.ResponseToolCalls) != 1 || a.ResponseToolCalls[0].Arguments != "ls" || a.ResponseToolCalls[0].Type != "custom_tool_call" {
		t.Fatalf("custom call lost or duplicated: %+v", a)
	}
	if len(b.Messages) != 1 || b.Messages[0].Role != "tool" || b.Messages[0].ToolCallID != "c1" || b.Messages[0].Text != "files" || len(b.ProtocolInputs) != 1 {
		t.Fatalf("custom result/state misclassified: %+v", b)
	}
}
