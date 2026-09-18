package pipeline

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/protocol"
)

// NMessage is a provider-neutral message view.
type NMessage struct {
	Role       string      `json:"role"`
	Text       string      `json:"text,omitempty"`
	ToolCalls  []NToolCall `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
	Hash       string      `json:"hash"`
}

// NToolCall is a tool invocation requested by the model.
type NToolCall struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	ArgsHash  string `json:"args_hash,omitempty"`
	Type      string `json:"type,omitempty"`
	Arguments any    `json:"arguments,omitempty"`
}

// Normalized is stored in model_attempts.normalized / model_inferences.normalized.
type Normalized struct {
	APIMode            string         `json:"api_mode"`
	Model              string         `json:"model,omitempty"`
	Stream             bool           `json:"stream"`
	System             string         `json:"system,omitempty"`
	Messages           []NMessage     `json:"messages"`
	Tools              []string       `json:"tools,omitempty"`
	ProtocolInputs     []any          `json:"protocol_inputs,omitempty"`
	Params             map[string]any `json:"params,omitempty"`
	PreviousResponseID string         `json:"previous_response_id,omitempty"`
	ResponseID         string         `json:"response_id,omitempty"`
	ServerStateRefs    []string       `json:"server_state_refs,omitempty"`
	BodyUnavailable    bool           `json:"body_unavailable,omitempty"`
	// response side
	ResponseText      string         `json:"response_text,omitempty"`
	ResponseToolCalls []NToolCall    `json:"response_tool_calls,omitempty"`
	FinishReason      string         `json:"finish_reason,omitempty"`
	StreamTerminated  *bool          `json:"stream_terminated,omitempty"`
	Usage             map[string]any `json:"usage,omitempty"`
	MessageHashes     []string       `json:"message_hashes"`
	Fingerprint       string         `json:"fingerprint"`
	InputHash         string         `json:"input_hash"`
}

func sha(s ...string) string {
	h := sha256.New()
	for _, x := range s {
		h.Write([]byte(x))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (n *Normalized) finalize() {
	n.MessageHashes = n.MessageHashes[:0]
	for i := range n.Messages {
		m := &n.Messages[i]
		var tc []string
		for _, t := range m.ToolCalls {
			tc = append(tc, t.Name+":"+t.ArgsHash)
		}
		m.Hash = sha(m.Role, m.Text, strings.Join(tc, ","), m.ToolCallID)[:32]
		n.MessageHashes = append(n.MessageHashes, m.Hash)
	}
	tools := append([]string(nil), n.Tools...)
	sort.Strings(tools)
	n.Fingerprint = sha(normalizeWS(n.System), strings.Join(tools, ","))
	n.InputHash = sha(n.Model, n.System, strings.Join(n.MessageHashes, ","), n.PreviousResponseID)
	if len(n.ProtocolInputs) > 0 {
		state, _ := json.Marshal(n.ProtocolInputs)
		n.InputHash = sha(n.InputHash, string(state))
	}
}

func normalizeWS(s string) string { return strings.Join(strings.Fields(s), " ") }

func responsesToolCall(item map[string]any) NToolCall {
	argument := item["arguments"]
	if item["type"] == "custom_tool_call" {
		argument = item["input"]
	}
	id, _ := item["call_id"].(string)
	name, _ := item["name"].(string)
	kind, _ := item["type"].(string)
	return NToolCall{ID: id, Name: name, Type: kind, Arguments: argument, ArgsHash: argsHash(argument)}
}

func responsesToolNames(value any, prefix string, depth int) []string {
	tools, _ := value.([]any)
	var names []string
	for _, entry := range tools {
		tool, _ := entry.(map[string]any)
		name, _ := tool["name"].(string)
		kind, _ := tool["type"].(string)
		if name == "" {
			name = kind
		}
		name = prefix + name
		if kind == "namespace" && depth < 8 {
			names = append(names, responsesToolNames(tool["tools"], name+".", depth+1)...)
		} else if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// textOf flattens OpenAI/Anthropic/Gemini content shapes to text.
func textOf(v any) string {
	switch c := v.(type) {
	case nil:
		return ""
	case string:
		return c
	case []any:
		var sb strings.Builder
		for _, part := range c {
			if m, ok := part.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					sb.WriteString(t)
					continue
				}
				if t, ok := m["type"].(string); ok {
					sb.WriteString("[" + t + "]")
				}
			}
		}
		return sb.String()
	case map[string]any:
		if t, ok := c["text"].(string); ok {
			return t
		}
		b, _ := json.Marshal(c)
		return string(b)
	default:
		b, _ := json.Marshal(c)
		return string(b)
	}
}

func argsHash(v any) string {
	switch a := v.(type) {
	case string:
		return sha(a)[:16]
	default:
		b, _ := json.Marshal(a)
		return sha(string(b))[:16]
	}
}

// NormalizeRequest parses a provider request body.
func NormalizeRequest(apiMode string, body []byte) (*Normalized, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("request body is not a JSON object: %w", err)
	}
	n := &Normalized{APIMode: apiMode, Params: map[string]any{}}
	if unavailable, _ := req["_iorec_body_unavailable"].(bool); unavailable {
		n.BodyUnavailable = true
	}
	if m, ok := req["model"].(string); ok {
		n.Model = m
	}
	if s, ok := req["stream"].(bool); ok {
		n.Stream = s
	}
	for _, k := range []string{"temperature", "top_p", "max_tokens", "max_output_tokens", "max_completion_tokens", "reasoning_effort", "reasoning", "tool_choice", "store", "service_tier", "seed", "generate", "parallel_tool_calls", "text", "include", "truncation", "max_tool_calls", "prompt_cache_key", "prompt_cache_retention"} {
		if v, ok := req[k]; ok {
			n.Params[k] = v
		}
	}
	switch apiMode {
	case "chat_completions", "completions", "unknown":
		msgs, _ := req["messages"].([]any)
		for _, mv := range msgs {
			m, _ := mv.(map[string]any)
			role, _ := m["role"].(string)
			nm := NMessage{Role: role, Text: textOf(m["content"])}
			if role == "system" || role == "developer" {
				if n.System != "" {
					n.System += "\n"
				}
				n.System += nm.Text
			}
			if tcs, ok := m["tool_calls"].([]any); ok {
				for _, tv := range tcs {
					t, _ := tv.(map[string]any)
					fn, _ := t["function"].(map[string]any)
					name, _ := fn["name"].(string)
					id, _ := t["id"].(string)
					nm.ToolCalls = append(nm.ToolCalls, NToolCall{ID: id, Name: name, ArgsHash: argsHash(fn["arguments"])})
				}
			}
			if id, ok := m["tool_call_id"].(string); ok {
				nm.ToolCallID = id
			}
			n.Messages = append(n.Messages, nm)
		}
		if tools, ok := req["tools"].([]any); ok {
			for _, tv := range tools {
				t, _ := tv.(map[string]any)
				if fn, ok := t["function"].(map[string]any); ok {
					if name, ok := fn["name"].(string); ok {
						n.Tools = append(n.Tools, name)
					}
				} else if name, ok := t["name"].(string); ok {
					n.Tools = append(n.Tools, name)
				}
			}
		}
	case "responses", "codex_responses":
		if ins, ok := req["instructions"].(string); ok {
			n.System = ins
		}
		if prev, ok := req["previous_response_id"].(string); ok && prev != "" {
			n.PreviousResponseID = prev
			n.ServerStateRefs = append(n.ServerStateRefs, prev)
		}
		if conv, ok := req["conversation"]; ok && conv != nil {
			n.ServerStateRefs = append(n.ServerStateRefs, "conversation:"+textOf(conv))
		}
		switch in := req["input"].(type) {
		case string:
			n.Messages = append(n.Messages, NMessage{Role: "user", Text: in})
		case []any:
			for _, iv := range in {
				item, _ := iv.(map[string]any)
				typ, _ := item["type"].(string)
				switch typ {
				case "function_call", "custom_tool_call":
					n.Messages = append(n.Messages, NMessage{Role: "assistant", ToolCalls: []NToolCall{responsesToolCall(item)}})
				case "function_call_output", "custom_tool_call_output":
					id, _ := item["call_id"].(string)
					n.Messages = append(n.Messages, NMessage{Role: "tool", Text: textOf(item["output"]), ToolCallID: id})
				case "additional_tools":
					n.Tools = append(n.Tools, responsesToolNames(item["tools"], "", 0)...)
					n.ProtocolInputs = append(n.ProtocolInputs, item)
				case "message", "":
					role, _ := item["role"].(string)
					if role == "" {
						role = "user"
					}
					n.Messages = append(n.Messages, NMessage{Role: role, Text: textOf(item["content"])})
				default:
					// Protocol state (e.g. reasoning/encrypted state) is not a user
					// message. Keep its native shape instead of inventing a role.
					n.ProtocolInputs = append(n.ProtocolInputs, item)
				}
			}
		}
		n.Tools = append(n.Tools, responsesToolNames(req["tools"], "", 0)...)
	case "anthropic_messages":
		n.System = textOf(req["system"])
		msgs, _ := req["messages"].([]any)
		for _, mv := range msgs {
			m, _ := mv.(map[string]any)
			role, _ := m["role"].(string)
			nm := NMessage{Role: role}
			switch c := m["content"].(type) {
			case string:
				nm.Text = c
			case []any:
				var sb strings.Builder
				for _, pv := range c {
					p, _ := pv.(map[string]any)
					switch p["type"] {
					case "text":
						t, _ := p["text"].(string)
						sb.WriteString(t)
					case "tool_use":
						name, _ := p["name"].(string)
						id, _ := p["id"].(string)
						nm.ToolCalls = append(nm.ToolCalls, NToolCall{ID: id, Name: name, ArgsHash: argsHash(p["input"])})
					case "tool_result":
						id, _ := p["tool_use_id"].(string)
						nm.ToolCallID = id
						sb.WriteString(textOf(p["content"]))
					default:
						if t, ok := p["type"].(string); ok {
							sb.WriteString("[" + t + "]")
						}
					}
				}
				nm.Text = sb.String()
			}
			n.Messages = append(n.Messages, nm)
		}
		if tools, ok := req["tools"].([]any); ok {
			for _, tv := range tools {
				t, _ := tv.(map[string]any)
				if name, ok := t["name"].(string); ok {
					n.Tools = append(n.Tools, name)
				}
			}
		}
	case "gemini_generate":
		if si, ok := req["systemInstruction"].(map[string]any); ok {
			n.System = textOf(si["parts"])
		} else if si, ok := req["system_instruction"].(map[string]any); ok {
			n.System = textOf(si["parts"])
		}
		if cc, ok := req["cachedContent"].(string); ok && cc != "" {
			n.ServerStateRefs = append(n.ServerStateRefs, cc)
		}
		contents, _ := req["contents"].([]any)
		for _, cv := range contents {
			c, _ := cv.(map[string]any)
			role, _ := c["role"].(string)
			if role == "model" {
				role = "assistant"
			}
			nm := NMessage{Role: role}
			parts, _ := c["parts"].([]any)
			var sb strings.Builder
			for _, pv := range parts {
				p, _ := pv.(map[string]any)
				if t, ok := p["text"].(string); ok {
					sb.WriteString(t)
				}
				if fc, ok := p["functionCall"].(map[string]any); ok {
					name, _ := fc["name"].(string)
					nm.ToolCalls = append(nm.ToolCalls, NToolCall{Name: name, ArgsHash: argsHash(fc["args"])})
				}
				if fr, ok := p["functionResponse"].(map[string]any); ok {
					nm.Role = "tool"
					name, _ := fr["name"].(string)
					nm.ToolCallID = name
					sb.WriteString(textOf(fr["response"]))
				}
			}
			nm.Text = sb.String()
			n.Messages = append(n.Messages, nm)
		}
		if tools, ok := req["tools"].([]any); ok {
			for _, tv := range tools {
				t, _ := tv.(map[string]any)
				if fds, ok := t["functionDeclarations"].([]any); ok {
					for _, fv := range fds {
						f, _ := fv.(map[string]any)
						if name, ok := f["name"].(string); ok {
							n.Tools = append(n.Tools, name)
						}
					}
				}
			}
		}
	}
	n.finalize()
	return n, nil
}

// sseEvent is one parsed SSE event.
type sseEvent struct {
	Event string
	Data  string
}

func parseSSE(raw string) []sseEvent {
	var out []sseEvent
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var cur sseEvent
	var data []string
	flush := func() {
		if len(data) > 0 || cur.Event != "" {
			cur.Data = strings.Join(data, "\n")
			out = append(out, cur)
		}
		cur = sseEvent{}
		data = nil
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		k, v, _ := strings.Cut(line, ":")
		v = strings.TrimPrefix(v, " ")
		switch k {
		case "event":
			cur.Event = v
		case "data":
			data = append(data, v)
		}
	}
	flush()
	return out
}

// ApplyStream folds SSE events into the normalized response fields.
// It sets StreamTerminated when the provider's terminal marker was seen.
func ApplyStream(n *Normalized, chunks []string) {
	var text strings.Builder
	terminated := false
	toolCalls := map[int]*NToolCall{}
	toolArgs := map[int]*strings.Builder{}
	for _, raw := range chunks {
		for _, ev := range parseSSE(raw) {
			d := strings.TrimSpace(ev.Data)
			if d == "[DONE]" {
				terminated = true
				continue
			}
			if d == "" {
				continue
			}
			var obj map[string]any
			if json.Unmarshal([]byte(d), &obj) != nil {
				continue
			}
			switch n.APIMode {
			case "chat_completions", "completions", "unknown":
				if u, ok := obj["usage"].(map[string]any); ok && u != nil {
					n.Usage = u
				}
				if m, ok := obj["model"].(string); ok && n.Model == "" {
					n.Model = m
				}
				if id, ok := obj["id"].(string); ok {
					n.ResponseID = id
				}
				choices, _ := obj["choices"].([]any)
				for _, cv := range choices {
					c, _ := cv.(map[string]any)
					if fr, ok := c["finish_reason"].(string); ok && fr != "" {
						n.FinishReason = fr
					}
					delta, _ := c["delta"].(map[string]any)
					if t, ok := delta["content"].(string); ok {
						text.WriteString(t)
					}
					if tcs, ok := delta["tool_calls"].([]any); ok {
						for _, tv := range tcs {
							t, _ := tv.(map[string]any)
							idx := int(toFloat(t["index"]))
							if toolCalls[idx] == nil {
								toolCalls[idx] = &NToolCall{}
								toolArgs[idx] = &strings.Builder{}
							}
							if id, ok := t["id"].(string); ok && id != "" {
								toolCalls[idx].ID = id
							}
							if fn, ok := t["function"].(map[string]any); ok {
								if name, ok := fn["name"].(string); ok && name != "" {
									toolCalls[idx].Name = name
								}
								if a, ok := fn["arguments"].(string); ok {
									toolArgs[idx].WriteString(a)
								}
							}
						}
					}
				}
			case "anthropic_messages":
				typ, _ := obj["type"].(string)
				switch typ {
				case "message_start":
					if msg, ok := obj["message"].(map[string]any); ok {
						if m, ok := msg["model"].(string); ok && n.Model == "" {
							n.Model = m
						}
						if id, ok := msg["id"].(string); ok {
							n.ResponseID = id
						}
						if u, ok := msg["usage"].(map[string]any); ok {
							n.Usage = mergeUsage(n.Usage, u)
						}
					}
				case "content_block_start":
					if cb, ok := obj["content_block"].(map[string]any); ok && cb["type"] == "tool_use" {
						idx := int(toFloat(obj["index"]))
						name, _ := cb["name"].(string)
						id, _ := cb["id"].(string)
						toolCalls[idx] = &NToolCall{ID: id, Name: name}
						toolArgs[idx] = &strings.Builder{}
					}
				case "content_block_delta":
					delta, _ := obj["delta"].(map[string]any)
					if t, ok := delta["text"].(string); ok {
						text.WriteString(t)
					}
					if pj, ok := delta["partial_json"].(string); ok {
						idx := int(toFloat(obj["index"]))
						if toolArgs[idx] != nil {
							toolArgs[idx].WriteString(pj)
						}
					}
				case "message_delta":
					if delta, ok := obj["delta"].(map[string]any); ok {
						if sr, ok := delta["stop_reason"].(string); ok {
							n.FinishReason = sr
						}
					}
					if u, ok := obj["usage"].(map[string]any); ok {
						n.Usage = mergeUsage(n.Usage, u)
					}
				case "message_stop":
					terminated = true
				}
			case "responses", "codex_responses":
				typ, _ := obj["type"].(string)
				switch typ {
				case "response.output_text.delta":
					if t, ok := obj["delta"].(string); ok {
						text.WriteString(t)
					}
				case "response.output_item.done":
					if item, ok := obj["item"].(map[string]any); ok && (item["type"] == "function_call" || item["type"] == "custom_tool_call") {
						n.ResponseToolCalls = append(n.ResponseToolCalls, responsesToolCall(item))
					}
				case "response.completed", "response.incomplete", "response.failed":
					terminated = true
					n.FinishReason = strings.TrimPrefix(typ, "response.")
					if r, ok := obj["response"].(map[string]any); ok {
						if id, ok := r["id"].(string); ok {
							n.ResponseID = id
						}
						if u, ok := r["usage"].(map[string]any); ok {
							n.Usage = u
						}
						if m, ok := r["model"].(string); ok && n.Model == "" {
							n.Model = m
						}
					}
				}
			case "gemini_generate":
				cands, _ := obj["candidates"].([]any)
				for _, cv := range cands {
					c, _ := cv.(map[string]any)
					if content, ok := c["content"].(map[string]any); ok {
						parts, _ := content["parts"].([]any)
						for _, pv := range parts {
							p, _ := pv.(map[string]any)
							if t, ok := p["text"].(string); ok {
								text.WriteString(t)
							}
							if fc, ok := p["functionCall"].(map[string]any); ok {
								name, _ := fc["name"].(string)
								n.ResponseToolCalls = append(n.ResponseToolCalls, NToolCall{Name: name, ArgsHash: argsHash(fc["args"])})
							}
						}
					}
					if fr, ok := c["finishReason"].(string); ok && fr != "" {
						n.FinishReason = fr
						terminated = true
					}
				}
				if u, ok := obj["usageMetadata"].(map[string]any); ok {
					n.Usage = u
				}
			}
		}
	}
	indices := make([]int, 0, len(toolCalls))
	for index := range toolCalls {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	for _, index := range indices {
		tc := toolCalls[index]
		tc.ArgsHash = argsHash(toolArgs[index].String())
		n.ResponseToolCalls = append(n.ResponseToolCalls, *tc)
	}
	n.ResponseText = text.String()
	t := terminated
	n.StreamTerminated = &t
}

// ApplyResponseBody extracts response fields from a non-streaming body.
func ApplyResponseBody(n *Normalized, body []byte) {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return
	}
	if u, ok := obj["usage"].(map[string]any); ok {
		n.Usage = u
	}
	if u, ok := obj["usageMetadata"].(map[string]any); ok {
		n.Usage = u
	}
	if m, ok := obj["model"].(string); ok && n.Model == "" {
		n.Model = m
	}
	if id, ok := obj["id"].(string); ok {
		n.ResponseID = id
	}
	// Agent-native observer payloads (notably Hermes) wrap the provider result
	// instead of returning the wire response shape. Preserve that semantic L2
	// evidence even when the corresponding transport request is unavailable.
	if fr, ok := obj["finish_reason"].(string); ok && fr != "" {
		n.FinishReason = fr
	}
	if message, ok := obj["assistant_message"].(map[string]any); ok {
		n.ResponseText += textOf(message["content"])
		if calls, ok := message["tool_calls"].([]any); ok {
			for _, value := range calls {
				call, _ := value.(map[string]any)
				function, _ := call["function"].(map[string]any)
				name, _ := function["name"].(string)
				id, _ := call["id"].(string)
				n.ResponseToolCalls = append(n.ResponseToolCalls, NToolCall{ID: id, Name: name, ArgsHash: argsHash(function["arguments"])})
			}
		}
	}
	if providerError, ok := obj["error"].(map[string]any); ok && n.ResponseText == "" {
		n.ResponseText = textOf(providerError["message"])
		if n.FinishReason == "" {
			n.FinishReason = "error"
		}
	}
	switch n.APIMode {
	case "chat_completions", "completions", "unknown":
		choices, _ := obj["choices"].([]any)
		for _, cv := range choices {
			c, _ := cv.(map[string]any)
			if fr, ok := c["finish_reason"].(string); ok {
				n.FinishReason = fr
			}
			msg, _ := c["message"].(map[string]any)
			n.ResponseText += textOf(msg["content"])
			if tcs, ok := msg["tool_calls"].([]any); ok {
				for _, tv := range tcs {
					t, _ := tv.(map[string]any)
					fn, _ := t["function"].(map[string]any)
					name, _ := fn["name"].(string)
					id, _ := t["id"].(string)
					n.ResponseToolCalls = append(n.ResponseToolCalls, NToolCall{ID: id, Name: name, ArgsHash: argsHash(fn["arguments"])})
				}
			}
		}
	case "anthropic_messages":
		if sr, ok := obj["stop_reason"].(string); ok {
			n.FinishReason = sr
		}
		content, _ := obj["content"].([]any)
		for _, pv := range content {
			p, _ := pv.(map[string]any)
			if t, ok := p["text"].(string); ok {
				n.ResponseText += t
			}
			if p["type"] == "tool_use" {
				name, _ := p["name"].(string)
				id, _ := p["id"].(string)
				n.ResponseToolCalls = append(n.ResponseToolCalls, NToolCall{ID: id, Name: name, ArgsHash: argsHash(p["input"])})
			}
		}
	case "responses", "codex_responses":
		if st, ok := obj["status"].(string); ok {
			n.FinishReason = st
		}
		out, _ := obj["output"].([]any)
		for _, iv := range out {
			item, _ := iv.(map[string]any)
			switch item["type"] {
			case "message":
				n.ResponseText += textOf(item["content"])
			case "function_call", "custom_tool_call":
				n.ResponseToolCalls = append(n.ResponseToolCalls, responsesToolCall(item))
			}
		}
	case "gemini_generate":
		cands, _ := obj["candidates"].([]any)
		for _, cv := range cands {
			c, _ := cv.(map[string]any)
			if fr, ok := c["finishReason"].(string); ok {
				n.FinishReason = fr
			}
			if content, ok := c["content"].(map[string]any); ok {
				n.ResponseText += textOf(content["parts"])
			}
		}
	}
	t := true
	n.StreamTerminated = &t
}

func mergeUsage(a, b map[string]any) map[string]any {
	if a == nil {
		a = map[string]any{}
	}
	for k, v := range b {
		a[k] = v
	}
	return a
}

func toFloat(v any) float64 {
	switch f := v.(type) {
	case float64:
		return f
	case int:
		return float64(f)
	case json.Number:
		x, _ := f.Float64()
		return x
	}
	return 0
}

// bodyBytes returns the inline body or fetches the referenced blob.
func (d *Deps) bodyBytes(ctx context.Context, project string, inline json.RawMessage, ref []byte) ([]byte, bool, error) {
	const maximum = 64 << 20
	if len(inline) > 0 {
		if len(inline) > maximum {
			return nil, false, fmt.Errorf("inline body exceeds processing limit %d", maximum)
		}
		// Decode the protocol's binary-safe inline wrapper before normalization.
		var wrap struct {
			RawBase64 string `json:"raw_base64"`
		}
		if json.Unmarshal(inline, &wrap) == nil && wrap.RawBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(wrap.RawBase64)
			if err != nil || len(decoded) > maximum {
				return nil, false, nil
			}
			return decoded, true, nil
		}
		return inline, true, nil
	}
	if len(ref) == 0 {
		return nil, false, nil
	}
	var key string
	var declaredSize int64
	err := d.DB.Pool.QueryRow(ctx, `select object_key, size from blobs where project_id=$1 and sha256=$2`, project, ref).Scan(&key, &declaredSize)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if declaredSize < 0 || declaredSize > maximum {
		return nil, false, nil
	}
	rc, err := d.Obj.Get(ctx, key)
	if errors.Is(err, objstore.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maximum+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maximum || int64(len(b)) != declaredSize {
		return nil, false, fmt.Errorf("blob object length does not match its catalog entry")
	}
	digest := sha256.Sum256(b)
	if subtle.ConstantTimeCompare(digest[:], ref) != 1 {
		return nil, false, fmt.Errorf("blob object digest does not match its catalog key")
	}
	return b, true, nil
}

type bodyChunkMetadata struct {
	Sequence     int64  `json:"chunk_sequence"`
	CapturedSize int64  `json:"captured_size"`
	ObservedSize int64  `json:"observed_size"`
	SHA256       string `json:"sha256"`
}

type websocketFrameMetadata struct {
	Direction       string `json:"direction"`
	MessageSequence int64  `json:"message_sequence"`
	Opcode          string `json:"opcode"`
	ObservedSize    int64  `json:"observed_size"`
	CapturedSize    int64  `json:"captured_size"`
	SHA256          string `json:"sha256"`
}

type websocketFinishMetadata struct {
	CaptureFailed    bool            `json:"capture_failed"`
	ClientMessages   int64           `json:"client_messages"`
	UpstreamMessages int64           `json:"upstream_messages"`
	Reason           string          `json:"reason"`
	ErrorDetail      json.RawMessage `json:"error_detail"`
}

// attemptBodyBytes returns an attempt body in wire order. New recorder events
// intentionally store every transport read as a separate immutable blob, so a
// multi-chunk body cannot be represented by model_attempts.*_body_ref alone.
func (d *Deps) attemptBodyBytes(ctx context.Context, project, run, nativeID, chunkEvent string, inline json.RawMessage, ref []byte) ([]byte, bool, error) {
	if body, ok, err := d.bodyBytes(ctx, project, inline, ref); err != nil || ok {
		return body, ok, err
	}
	events, err := d.loadRunEvents(ctx, run, `and e.attempt_id=$2 and e.event=$3`, nativeID, chunkEvent)
	if err != nil {
		return nil, false, err
	}
	if len(events) == 0 {
		return nil, false, nil
	}
	const maximum = 64 << 20
	var out bytes.Buffer
	expectedSequence := int64(1)
	for _, event := range events {
		var metadata bodyChunkMetadata
		if err := json.Unmarshal(event.Payload, &metadata); err != nil {
			return nil, false, fmt.Errorf("%s seq %d has invalid chunk metadata: %w", chunkEvent, event.Seq, err)
		}
		if metadata.Sequence != expectedSequence {
			return nil, false, fmt.Errorf("%s chunk sequence gap: expected %d, got %d", chunkEvent, expectedSequence, metadata.Sequence)
		}
		expectedSequence++
		if metadata.CapturedSize < 0 || metadata.ObservedSize < metadata.CapturedSize || event.RawTruncated || metadata.CapturedSize != metadata.ObservedSize {
			return nil, false, nil
		}
		if metadata.CapturedSize == 0 {
			emptyDigest := sha256.Sum256(nil)
			declaredDigest := strings.TrimPrefix(strings.ToLower(metadata.SHA256), "sha256:")
			if declaredDigest != "" && declaredDigest != hex.EncodeToString(emptyDigest[:]) {
				return nil, false, fmt.Errorf("%s chunk %d has an invalid empty-body digest", chunkEvent, metadata.Sequence)
			}
			if event.PayloadSize != nil && *event.PayloadSize != 0 {
				return nil, false, fmt.Errorf("%s chunk %d has a non-zero event size for an empty body", chunkEvent, metadata.Sequence)
			}
			if len(event.PayloadSHA) > 0 && subtle.ConstantTimeCompare(event.PayloadSHA, emptyDigest[:]) != 1 {
				return nil, false, fmt.Errorf("%s chunk %d has a mismatched empty-body event digest", chunkEvent, metadata.Sequence)
			}
			continue
		}
		if len(event.PayloadSHA) == 0 || event.PayloadSize == nil || *event.PayloadSize != metadata.CapturedSize {
			return nil, false, nil
		}
		if strings.TrimPrefix(strings.ToLower(metadata.SHA256), "sha256:") != hex.EncodeToString(event.PayloadSHA) {
			return nil, false, fmt.Errorf("%s chunk %d metadata digest does not match its event reference", chunkEvent, metadata.Sequence)
		}
		part, ok, err := d.bodyBytes(ctx, project, nil, event.PayloadSHA)
		if err != nil {
			return nil, false, err
		}
		if !ok || int64(len(part)) != metadata.CapturedSize {
			return nil, false, nil
		}
		if out.Len() > maximum-len(part) {
			return nil, false, fmt.Errorf("reassembled %s exceeds processing limit %d", chunkEvent, maximum)
		}
		_, _ = out.Write(part)
	}
	return out.Bytes(), true, nil
}

func headerValue(headers json.RawMessage, name string) string {
	var values map[string]any
	if json.Unmarshal(headers, &values) != nil {
		return ""
	}
	for key, value := range values {
		if !strings.EqualFold(key, name) {
			continue
		}
		switch typed := value.(type) {
		case string:
			return typed
		case []any:
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				if text, ok := item.(string); ok {
					parts = append(parts, text)
				}
			}
			return strings.Join(parts, ",")
		}
	}
	return ""
}

func requestBodyExpected(apiMode, method string, headers json.RawMessage) bool {
	if apiMode != "unknown" {
		return true
	}
	if value := strings.TrimSpace(headerValue(headers, "content-length")); value != "" && value != "0" {
		return true
	}
	if headerValue(headers, "transfer-encoding") != "" {
		return true
	}
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func responseBodyExpected(method string, status *int, headers json.RawMessage) bool {
	if strings.EqualFold(method, "HEAD") || (status != nil && (*status == http.StatusNoContent || *status == http.StatusNotModified)) {
		return false
	}
	return strings.TrimSpace(headerValue(headers, "content-length")) != "0"
}

func readDecodedBody(reader io.Reader) ([]byte, error) {
	const maximum = 64 << 20
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maximum {
		return nil, fmt.Errorf("decoded response body exceeds processing limit %d", maximum)
	}
	return body, nil
}

// decodeContentEncoding reverses HTTP Content-Encoding in RFC order and keeps
// decompression bounded. Recorder blobs remain untouched wire evidence.
func decodeContentEncoding(body []byte, contentEncoding string) ([]byte, error) {
	encodings := strings.Split(strings.ToLower(contentEncoding), ",")
	decoded := body
	for i := len(encodings) - 1; i >= 0; i-- {
		encoding := strings.TrimSpace(encodings[i])
		if encoding == "" || encoding == "identity" {
			continue
		}
		var (
			reader io.ReadCloser
			err    error
		)
		switch encoding {
		case "gzip", "x-gzip":
			reader, err = gzip.NewReader(bytes.NewReader(decoded))
		case "deflate":
			reader, err = zlib.NewReader(bytes.NewReader(decoded))
			if err != nil {
				reader = flate.NewReader(bytes.NewReader(decoded))
				err = nil
			}
		case "br":
			reader = io.NopCloser(brotli.NewReader(bytes.NewReader(decoded)))
		case "zstd":
			var zr *zstd.Decoder
			zr, err = zstd.NewReader(bytes.NewReader(decoded), zstd.WithDecoderMaxMemory(64<<20), zstd.WithDecoderMaxWindow(64<<20))
			if err == nil {
				reader = zr.IOReadCloser()
			}
		default:
			return nil, fmt.Errorf("unsupported content-encoding %q", encoding)
		}
		if err != nil {
			return nil, fmt.Errorf("decode content-encoding %s: %w", encoding, err)
		}
		decoded, err = readDecodedBody(reader)
		closeErr := reader.Close()
		if err != nil {
			return nil, fmt.Errorf("decode content-encoding %s: %w", encoding, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close content-encoding %s decoder: %w", encoding, closeErr)
		}
	}
	return decoded, nil
}

// Normalize computes normalized views for attempts and observed inferences touched by the batch.
func (d *Deps) Normalize(ctx context.Context, j *jobs.Job) error {
	rec := *j.RecordingID
	run := runIDOf(j)
	unlock, lockErr := d.lockProjection(ctx, run)
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
	var input struct {
		batchRef
		BlobArrived string `json:"blob_arrived"`
	}
	_ = json.Unmarshal(j.InputRef, &input)
	var attemptIDs []string
	var err error
	if input.BlobArrived != "" {
		ref, _ := hex.DecodeString(input.BlobArrived)
		attemptIDs, err = scanStrings(d.DB.Pool.Query(ctx, `select id from model_attempts where capture_run_id=$1 and (request_body_ref=$2 or response_body_ref=$2)`, run, ref))
		if err == nil {
			var nativeIDs []string
			nativeIDs, err = scanStrings(d.DB.Pool.Query(ctx, `select distinct e.attempt_id from recording_events e join recordings r on r.id=e.recording_id where r.capture_run_id=$1 and e.payload_sha256=$2 and e.attempt_id is not null`, run, ref))
			seen := make(map[string]struct{}, len(attemptIDs)+len(nativeIDs))
			for _, id := range attemptIDs {
				seen[id] = struct{}{}
			}
			for _, nativeID := range nativeIDs {
				id := AttemptKey(run, nativeID)
				if _, exists := seen[id]; !exists {
					attemptIDs = append(attemptIDs, id)
					seen[id] = struct{}{}
				}
			}
		}
	} else {
		attemptIDs, err = scanStrings(d.DB.Pool.Query(ctx, `select distinct attempt_id from recording_events where recording_id=$1 and seq between $2 and $3 and attempt_id is not null`, rec, input.FirstSeq, input.LastSeq))
		for i := range attemptIDs {
			attemptIDs[i] = AttemptKey(run, attemptIDs[i])
		}
	}
	if err != nil {
		return err
	}
	for _, id := range attemptIDs {
		if err := d.normalizeAttempt(ctx, j, run, id); err != nil {
			return fmt.Errorf("normalize attempt %s: %w", id, err)
		}
	}
	infIDs, err := scanStrings(d.DB.Pool.Query(ctx, `select distinct inference_id from recording_events where recording_id=$1 and seq between $2 and $3 and inference_id is not null and event in ('inference_request','inference_response','inference_error','pre_api_request','post_api_request','api_request_error')`, rec, input.FirstSeq, input.LastSeq))
	if err != nil {
		return err
	}
	for _, id := range infIDs {
		if err := d.normalizeInference(ctx, InferenceKey(run, id)); err != nil {
			return fmt.Errorf("normalize inference %s: %w", id, err)
		}
	}
	if input.BatchID != "" {
		// mark batch parsed and advance parsed_seq over contiguous parsed batches
		if err := d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `update batches set parsed_at=now() where recording_id=$1 and batch_id=$2`, rec, input.BatchID); err != nil {
				return err
			}
			var parsed int64
			if err := tx.QueryRow(ctx, `select parsed_seq from recordings where id=$1 for update`, rec).Scan(&parsed); err != nil {
				return err
			}
			for i := 0; i < 100000; i++ {
				var last int64
				err := tx.QueryRow(ctx, `select last_seq from batches where recording_id=$1 and first_seq=$2 and parsed_at is not null`, rec, parsed+1).Scan(&last)
				if errors.Is(err, pgx.ErrNoRows) {
					break
				}
				if err != nil {
					return err
				}
				parsed = last
			}
			if _, err := tx.Exec(ctx, `update recordings set parsed_seq=$2, updated_at=now() where id=$1`, rec, parsed); err != nil {
				return err
			}
			resolveInput := map[string]any{"recording_id": rec, "parsed_seq": parsed}
			if input.Reprocess != "" {
				resolveInput["reprocess"] = input.Reprocess
			}
			if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: j.ProjectID, Type: jobs.TypeResolve, CaptureRunID: run, InputRef: resolveInput, ProcessorVersion: ResolverVersion, Priority: 6}); err != nil {
				return err
			}
			return d.publishTx(ctx, tx, j.ProjectID, "recording", rec, "parsed_seq", parsed)
		}); err != nil {
			return err
		}
	} else {
		return d.enqueueNext(ctx, j.ProjectID, jobs.TypeResolve, "", run, map[string]any{"recording_id": rec, "blob_arrived": input.BlobArrived}, ResolverVersion, 6)
	}
	return nil
}

func scanStrings(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *Deps) normalizeAttempt(ctx context.Context, j *jobs.Job, run, id string) error {
	var apiMode, terminal, nativeID, method, attemptProtocol string
	var reqInline, respInline, reqHeaders, respHeaders json.RawMessage
	var reqRef, respRef []byte
	var sseCount int
	var status *int
	var url *string
	if err := d.DB.Pool.QueryRow(ctx, `select coalesce(api_mode,'unknown'), terminal_state, request_body, request_body_ref, response_body, response_body_ref, request_headers, response_headers, sse_event_count, url, native_id, coalesce(method,''), status_code, coalesce(protocol,'') from model_attempts where id=$1`, id).
		Scan(&apiMode, &terminal, &reqInline, &reqRef, &respInline, &respRef, &reqHeaders, &respHeaders, &sseCount, &url, &nativeID, &method, &status, &attemptProtocol); err != nil {
		return err
	}
	if apiMode == "unknown" && url != nil {
		apiMode = detectAPIMode(*url)
	}
	if strings.EqualFold(attemptProtocol, "websocket") {
		return d.normalizeWebSocketCalls(ctx, j, run, id, nativeID, apiMode)
	}
	if strings.EqualFold(attemptProtocol, "websocket_message") {
		// Child calls are rebuilt only with their connection snapshot.
		return nil
	}
	body, ok, err := d.attemptBodyBytes(ctx, j.ProjectID.String(), run, nativeID, protocol.EvRequestBodyChunk, reqInline, reqRef)
	if err != nil {
		return err
	}
	var n *Normalized
	if !ok {
		n = &Normalized{APIMode: apiMode, BodyUnavailable: requestBodyExpected(apiMode, method, reqHeaders)}
		n.finalize()
	} else {
		n, err = NormalizeRequest(apiMode, body)
		if err != nil {
			n = &Normalized{APIMode: apiMode, BodyUnavailable: true, Params: map[string]any{"parse_error": err.Error()}}
			n.finalize()
		}
	}
	// Prefer the complete wire body. Besides supporting chunked bodies, this is
	// required when an upstream compresses SSE: capture-time SSE parsing sees
	// encoded bytes, while the platform can safely decode the complete stream.
	responseBody, responseAvailable, err := d.attemptBodyBytes(ctx, j.ProjectID.String(), run, nativeID, protocol.EvResponseBodyChunk, respInline, respRef)
	if err != nil {
		return err
	}
	if responseAvailable {
		responseBody, err = decodeContentEncoding(responseBody, headerValue(respHeaders, "content-encoding"))
		if err != nil {
			return err
		}
		if sseCount > 0 || strings.Contains(strings.ToLower(headerValue(respHeaders, "content-type")), "text/event-stream") {
			ApplyStream(n, []string{string(responseBody)})
		} else {
			ApplyResponseBody(n, responseBody)
		}
	} else {
		chunks, err := d.loadRunEvents(ctx, run, `and e.attempt_id=$2 and e.event in ('sse_chunk','sse_event')`, nativeID)
		if err != nil {
			return err
		}
		if len(chunks) == 0 {
			if terminal == "completed" && responseBodyExpected(method, status, respHeaders) {
				n.BodyUnavailable = true
			}
		} else {
			var raws []string
			streamBytes := 0
			for _, c := range chunks {
				if c.Event == protocol.EvSSEEvent {
					raw, available, err := d.bodyBytes(ctx, j.ProjectID.String(), nil, c.PayloadSHA)
					if err != nil {
						return err
					}
					if !available || c.RawTruncated || streamBytes > (64<<20)-len(raw) {
						n.BodyUnavailable = true
						continue
					}
					streamBytes += len(raw)
					raws = append(raws, string(raw))
					continue
				}
				var p struct {
					Raw   string `json:"raw"`
					Event string `json:"event"`
					Data  string `json:"data"`
				}
				if json.Unmarshal(c.Payload, &p) == nil {
					if p.Raw != "" {
						raws = append(raws, p.Raw)
					} else if p.Data != "" || p.Event != "" {
						s := ""
						if p.Event != "" {
							s += "event: " + p.Event + "\n"
						}
						s += "data: " + p.Data + "\n\n"
						raws = append(raws, s)
					}
				}
			}
			ApplyStream(n, raws)
		}
	}
	if n.StreamTerminated != nil {
		if !*n.StreamTerminated && terminal == "completed" {
			terminal = "truncated"
		} else if *n.StreamTerminated && responseAvailable && status != nil && *status >= 200 && *status < 300 && (terminal == "truncated" || terminal == "cancelled") {
			terminal = "completed"
		}
	}
	nb, _ := json.Marshal(n)
	var usage any
	if n.Usage != nil {
		usage, _ = json.Marshal(n.Usage)
	}
	fp, _ := hex.DecodeString(n.Fingerprint)
	ih, _ := hex.DecodeString(n.InputHash)
	_, err = d.DB.Pool.Exec(ctx, `update model_attempts set normalized=$2, api_mode=$3, model=coalesce(nullif($4,''), model), usage=coalesce($5::jsonb, usage), response_text=$6, request_fingerprint=$7, input_hash=$8, terminal_state=case when $9='unknown' then terminal_state else $9 end, processor_version=$10, updated_at=now() where id=$1`,
		id, nb, n.APIMode, n.Model, usage, nilIfEmpty(truncateStr(n.ResponseText, 200000)), fp, ih, terminal, NormalizerVersion)
	return err
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (d *Deps) normalizeInference(ctx context.Context, id string) error {
	var apiMode string
	var req, resp json.RawMessage
	var err error
	if err := d.DB.Pool.QueryRow(ctx, `select coalesce(api_mode,'unknown'), request, response from model_inferences where id=$1`, id).Scan(&apiMode, &req, &resp); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if len(req) == 0 && len(resp) == 0 {
		return nil
	}
	if apiMode == "unknown" {
		// Hermes hooks label api_mode as chat_completions/responses/anthropic_messages; fall back by shape
		var probe map[string]any
		_ = json.Unmarshal(req, &probe)
		switch {
		case probe["messages"] != nil && probe["system"] != nil:
			apiMode = "anthropic_messages"
		case probe["input"] != nil:
			apiMode = "responses"
		case probe["contents"] != nil:
			apiMode = "gemini_generate"
		default:
			apiMode = "chat_completions"
		}
	}
	var n *Normalized
	if len(req) > 0 {
		n, err = NormalizeRequest(apiMode, req)
	}
	if n == nil || err != nil {
		n = &Normalized{APIMode: apiMode, BodyUnavailable: true}
		if err != nil {
			n.Params = map[string]any{"parse_error": err.Error()}
		}
		n.finalize()
	}
	if len(resp) > 0 {
		ApplyResponseBody(n, resp)
	}
	nb, _ := json.Marshal(n)
	fp, _ := hex.DecodeString(n.Fingerprint)
	ih, _ := hex.DecodeString(n.InputHash)
	var usage any
	if n.Usage != nil {
		usage, _ = json.Marshal(n.Usage)
	}
	_, err = d.DB.Pool.Exec(ctx, `update model_inferences set normalized=$2, api_mode=$3, model=coalesce(nullif($4,''), model), request_fingerprint=$5, input_hash=$6, usage=coalesce($7::jsonb, usage), processor_version=$8, updated_at=now() where id=$1`,
		id, nb, n.APIMode, n.Model, fp, ih, usage, NormalizerVersion)
	return err
}

func (d *Deps) publishTx(ctx context.Context, tx pgx.Tx, project interface{ String() string }, entityType, id, kind string, rev int64) error {
	_, err := tx.Exec(ctx, `insert into notifications_outbox(project_id, entity_type, entity_id, kind, revision) values($1,$2,$3,$4,$5)`, project.String(), entityType, id, kind, rev)
	return err
}
