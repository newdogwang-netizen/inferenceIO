// fake-collector generates realistic iorec batches (a Hermes-like agent run
// through a proxy with observer hooks) and uploads them, optionally injecting
// faults: dropped batches, reordering, corrupted hashes, disconnects.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/heidihealth/iorec-platform/internal/protocol"
)

type gen struct {
	run, rec string
	seq      int64
	t        time.Time
	mono     int64
	events   []protocol.Event
	blobs    map[string][]byte
}

func (g *gen) emit(source, event string, ids protocol.IDs, payload any) {
	g.seq++
	g.mono += 1_000_000 + rand.Int63n(30_000_000)
	g.t = g.t.Add(time.Duration(1_000_000 + rand.Int63n(30_000_000)))
	ev := protocol.Event{
		SchemaVersion: 1,
		EventID:       uuid.Must(uuid.NewV7()).String(),
		RunID:         g.run,
		RecordingID:   g.rec,
		Seq:           g.seq,
		MonotonicNS:   g.mono,
		WallTime:      g.t.UTC(),
		Source:        source,
		Event:         event,
		IDs:           ids,
		Redaction:     &protocol.Redaction{Policy: "default"},
	}
	if payload != nil {
		b, _ := json.Marshal(payload)
		if len(b) > 16<<10 {
			sum := sha256.Sum256(b)
			h := hex.EncodeToString(sum[:])
			g.blobs[h] = b
			ev.PayloadRef = &protocol.PayloadRef{SHA256: "sha256:" + h, Size: int64(len(b)), MediaType: "application/json"}
		} else {
			ev.Payload = b
		}
	}
	g.events = append(g.events, ev)
}

type msg = map[string]any

// scenario builds one Hermes-like run: 3 turns, a tool call, a 500 retry, a fallback to a second host, a cancelled stream, a subagent.
func scenario(run string, pid int) *gen {
	g := &gen{run: run, rec: run + "#0000", t: time.Now().Add(-2 * time.Minute), blobs: map[string][]byte{}}
	g.emit("runner", "run_start", protocol.IDs{PID: pid}, msg{"command": "hermes", "cwd": "/home/dev/project", "agent_kind": "hermes", "agent_version": "0.16.0", "binary_sha256": strings.Repeat("ab", 32)})
	g.emit("runner", "capability_report", protocol.IDs{PID: pid}, msg{"schema": "iorec.capabilities.v1", "transport": msg{"http_body": "visible", "sse": "visible", "websocket": "absent", "http2_decode": "absent", "http3": "detect_only"},
		"sources":           msg{"proxy": true, "hook": []string{"hermes"}, "ebpf": msg{"available": false, "reason": "no CAP_BPF"}, "keylog": msg{"available": true, "runtimes": []string{"python"}}, "pcap": msg{"available": false}, "pty": false},
		"runtime_inventory": msg{"agents_detected": []msg{{"kind": "hermes", "version": "0.16.0", "install": "venv"}}, "tls_surfaces": []msg{{"lib": "openssl", "version": "3.5.5", "link": "dynamic", "status": "verified"}}, "unknown_tls_surfaces": 0}})
	g.emit("runner", "tls_surface", protocol.IDs{PID: pid}, msg{"lib": "openssl", "version": "3.5.5", "link": "dynamic", "status": "verified", "pid": pid})
	sess := "20260915_101500_ab12cd"
	g.emit("hook", "session_start", protocol.IDs{AgentSessionID: sess, PID: pid}, msg{"platform": "cli", "model": "accounts/fireworks/models/deepseek-v4-pro-0813"})
	system := "You are Hermes, a helpful coding agent. Persist knowledge, create skills, be concise."
	tools := []msg{{"type": "function", "function": msg{"name": "terminal", "parameters": msg{"type": "object"}}}, {"type": "function", "function": msg{"name": "read_file", "parameters": msg{"type": "object"}}}}
	history := []msg{{"role": "system", "content": system}}
	model := "accounts/fireworks/models/deepseek-v4-pro-0813"
	infN := 0
	callID := 0
	// helper: one logical inference with attempts
	inference := func(turn string, host string, plan []string, toolCall bool, reply string) string {
		infN++
		infID := fmt.Sprintf("api-%s-%03d", sess, infN)
		req := msg{"model": model, "messages": history, "tools": tools, "stream": true, "temperature": 0.7, "stream_options": msg{"include_usage": true}}
		g.emit("hook", "inference_request", protocol.IDs{AgentSessionID: sess, TurnID: turn, InferenceID: infID, PID: pid}, msg{"provider": "custom", "model": model, "api_mode": "chat_completions", "base_url": "https://" + host + "/inference/v1", "api_call_count": infN, "request": req})
		var lastAttempt string
		for i, kind := range plan {
			attemptID := fmt.Sprintf("att-%03d-%d", infN, i)
			lastAttempt = attemptID
			conn := fmt.Sprintf("conn-%d", infN*10+i)
			curHost := host
			if kind == "fallback" {
				curHost = "openrouter.ai"
			}
			ids := protocol.IDs{AttemptID: attemptID, ConnectionID: conn, PID: pid, InferenceID: infID}
			g.emit("proxy", "connection_open", protocol.IDs{ConnectionID: conn, PID: pid}, msg{"remote": curHost + ":443", "alpn": "http/1.1"})
			g.emit("proxy", "attempt_start", ids, msg{"method": "POST", "url": "https://" + curHost + "/inference/v1/chat/completions", "host": curHost, "protocol": "http/1.1"})
			g.emit("proxy", "request_headers", ids, msg{"headers": msg{"content-type": "application/json", "user-agent": "OpenAI/Python 2.24.0", "x-stainless-retry-count": fmt.Sprint(i)}})
			ev := g.events[len(g.events)-1]
			_ = ev
			g.events[len(g.events)-1].Redaction = &protocol.Redaction{Policy: "default", Fields: []string{"authorization"}}
			g.emit("proxy", "request_body", ids, req)
			switch kind {
			case "500":
				g.emit("proxy", "response_headers", ids, msg{"status": 500, "headers": msg{"content-type": "application/json"}})
				g.emit("proxy", "response_body", ids, msg{"error": msg{"message": "upstream overloaded", "type": "server_error"}})
				g.emit("proxy", "attempt_end", ids, msg{"reason": "completed", "status": 500, "duration_ms": 120})
			case "reset":
				g.emit("proxy", "attempt_error", ids, msg{"class": "connection_reset", "message": "read: connection reset by peer"})
			case "cancel":
				g.emit("proxy", "response_headers", ids, msg{"status": 200, "headers": msg{"content-type": "text/event-stream"}})
				for k := 0; k < 4; k++ {
					chunk := msg{"id": "chatcmpl-" + attemptID, "object": "chat.completion.chunk", "model": model, "choices": []msg{{"index": 0, "delta": msg{"content": []string{"Let", " me", " look", " at"}[k]}}}}
					b, _ := json.Marshal(chunk)
					g.emit("proxy", "sse_chunk", ids, msg{"raw": "data: " + string(b) + "\n\n"})
				}
				g.emit("proxy", "attempt_cancel", ids, msg{"reason": "client_cancelled", "signal": "SIGINT"})
			default: // ok / fallback
				g.emit("proxy", "response_headers", ids, msg{"status": 200, "headers": msg{"content-type": "text/event-stream"}})
				words := strings.Fields(reply)
				var toolArgs string
				if toolCall {
					callID++
					toolArgs = fmt.Sprintf(`{"command":"ls -la src/ # %d"}`, callID)
					head := msg{"id": "chatcmpl-" + attemptID, "object": "chat.completion.chunk", "model": model, "choices": []msg{{"index": 0, "delta": msg{"tool_calls": []msg{{"index": 0, "id": fmt.Sprintf("call_%03d", callID), "type": "function", "function": msg{"name": "terminal", "arguments": ""}}}}}}}
					b, _ := json.Marshal(head)
					g.emit("proxy", "sse_chunk", ids, msg{"raw": "data: " + string(b) + "\n\n"})
					for _, piece := range splitN(toolArgs, 3) {
						c := msg{"id": "chatcmpl-" + attemptID, "object": "chat.completion.chunk", "model": model, "choices": []msg{{"index": 0, "delta": msg{"tool_calls": []msg{{"index": 0, "function": msg{"arguments": piece}}}}}}}
						b, _ := json.Marshal(c)
						g.emit("proxy", "sse_chunk", ids, msg{"raw": "data: " + string(b) + "\n\n"})
					}
				}
				for k, wd := range words {
					if k > 0 {
						wd = " " + wd
					}
					chunk := msg{"id": "chatcmpl-" + attemptID, "object": "chat.completion.chunk", "model": model, "choices": []msg{{"index": 0, "delta": msg{"content": wd}}}}
					b, _ := json.Marshal(chunk)
					g.emit("proxy", "sse_chunk", ids, msg{"raw": "data: " + string(b) + "\n\n"})
				}
				fr := "stop"
				if toolCall {
					fr = "tool_calls"
				}
				promptTok := 400 + 120*len(history)
				fin := msg{"id": "chatcmpl-" + attemptID, "object": "chat.completion.chunk", "model": model, "choices": []msg{{"index": 0, "delta": msg{}, "finish_reason": fr}}, "usage": msg{"prompt_tokens": promptTok, "completion_tokens": len(words) + 12, "total_tokens": promptTok + len(words) + 12}}
				b, _ := json.Marshal(fin)
				g.emit("proxy", "sse_chunk", ids, msg{"raw": "data: " + string(b) + "\n\ndata: [DONE]\n\n"})
				g.emit("proxy", "attempt_end", ids, msg{"reason": "completed", "status": 200, "duration_ms": 900 + rand.Intn(2000)})
				// hook response
				respMsg := msg{"role": "assistant", "content": reply}
				if toolCall {
					respMsg["content"] = nil
					respMsg["tool_calls"] = []msg{{"id": fmt.Sprintf("call_%03d", callID), "type": "function", "function": msg{"name": "terminal", "arguments": toolArgs}}}
				}
				g.emit("hook", "inference_response", protocol.IDs{AgentSessionID: sess, TurnID: turn, InferenceID: infID, PID: pid}, msg{"response": msg{"id": "chatcmpl-" + attemptID, "model": model, "choices": []msg{{"index": 0, "message": respMsg, "finish_reason": fr}}, "usage": fin["usage"]}, "usage": fin["usage"], "finish_reason": fr, "duration_ms": 1234})
				history = append(history, respMsg)
			}
			g.emit("proxy", "connection_close", protocol.IDs{ConnectionID: conn, PID: pid}, msg{"reason": "eof"})
		}
		_ = lastAttempt
		return infID
	}
	// turn 1: user asks, model calls tool, tool result, model answers (2 inferences)
	turn1 := "turn-1"
	g.emit("hook", "turn_start", protocol.IDs{AgentSessionID: sess, TurnID: turn1, PID: pid}, msg{"user_message_preview": "List the src directory and summarize"})
	history = append(history, msg{"role": "user", "content": "List the src directory and summarize what you see."})
	inference(turn1, "api.fireworks.ai", []string{"ok"}, true, "")
	g.emit("hook", "tool_call", protocol.IDs{AgentSessionID: sess, TurnID: turn1, PID: pid}, msg{"tool_name": "terminal", "tool_call_id": fmt.Sprintf("call_%03d", callID), "args_preview": "ls -la src/"})
	g.emit("hook", "tool_result", protocol.IDs{AgentSessionID: sess, TurnID: turn1, PID: pid}, msg{"tool_name": "terminal", "tool_call_id": fmt.Sprintf("call_%03d", callID), "status": "ok", "bytes": 812})
	history = append(history, msg{"role": "tool", "tool_call_id": fmt.Sprintf("call_%03d", callID), "content": "total 24\n-rw-r--r-- main.go\n-rw-r--r-- util.go\n-rw-r--r-- api.go"})
	inference(turn1, "api.fireworks.ai", []string{"500", "500", "ok"}, false, "The src directory has three Go files: main.go, util.go and api.go. It looks like a small HTTP service.")
	g.emit("hook", "turn_end", protocol.IDs{AgentSessionID: sess, TurnID: turn1, PID: pid}, nil)
	// turn 2: fallback provider path + subagent
	turn2 := "turn-2"
	g.emit("hook", "turn_start", protocol.IDs{AgentSessionID: sess, TurnID: turn2, PID: pid}, msg{"user_message_preview": "Delegate a review"})
	history = append(history, msg{"role": "user", "content": "Delegate a quick code review of api.go to a subagent, then tell me the verdict."})
	inference(turn2, "api.fireworks.ai", []string{"reset", "fallback"}, true, "")
	// subagent: separate session, different system prompt
	child := sess + "-sub1"
	g.emit("hook", "subagent_start", protocol.IDs{AgentSessionID: child, ParentSpanID: sess, TurnID: turn2, PID: pid}, msg{"child_session_id": child, "parent_session_id": sess, "parent_turn_id": turn2, "child_goal": "review api.go", "child_role": "reviewer"})
	saved := history
	history = []msg{{"role": "system", "content": "You are a focused code reviewer subagent. Return findings only."}, {"role": "user", "content": "Review api.go for bugs."}}
	sessMain := sess
	sess = child
	inference("sub-turn-1", "api.fireworks.ai", []string{"ok"}, false, "Found one issue: the handler ignores the error from json.Decode. Otherwise fine.")
	sess = sessMain
	history = saved
	g.emit("hook", "subagent_stop", protocol.IDs{AgentSessionID: child, ParentSpanID: sess, PID: pid}, msg{"child_session_id": child, "parent_session_id": sess, "status": "ok"})
	g.emit("hook", "tool_result", protocol.IDs{AgentSessionID: sess, TurnID: turn2, PID: pid}, msg{"tool_name": "terminal", "tool_call_id": fmt.Sprintf("call_%03d", callID), "status": "ok"})
	history = append(history, msg{"role": "tool", "tool_call_id": fmt.Sprintf("call_%03d", callID), "content": "Subagent verdict: one ignored error in json.Decode."})
	inference(turn2, "api.fireworks.ai", []string{"ok"}, false, "The reviewer found one issue: the handler ignores the json.Decode error. I recommend returning 400 on decode failure.")
	g.emit("hook", "turn_end", protocol.IDs{AgentSessionID: sess, TurnID: turn2, PID: pid}, nil)
	// turn 3: user cancels mid-stream
	turn3 := "turn-3"
	g.emit("hook", "turn_start", protocol.IDs{AgentSessionID: sess, TurnID: turn3, PID: pid}, msg{"user_message_preview": "Explain everything in detail"})
	history = append(history, msg{"role": "user", "content": "Explain the whole codebase in great detail."})
	inference(turn3, "api.fireworks.ai", []string{"cancel"}, false, "")
	g.emit("hook", "turn_end", protocol.IDs{AgentSessionID: sess, TurnID: turn3, PID: pid}, msg{"status": "interrupted"})
	g.emit("hook", "session_end", protocol.IDs{AgentSessionID: sess, PID: pid}, msg{"reason": "user_exit"})
	g.emit("runner", "run_end", protocol.IDs{PID: pid}, msg{"exit_code": 0})
	g.emit("runner", "manifest", protocol.IDs{PID: pid}, msg{"claim": "best-effort", "logical_inferences": infN, "capture_sources": []string{"proxy", "hook"}, "known_gaps": []string{"websocket not covered"}})
	return g
}

func splitN(s string, n int) []string {
	var out []string
	step := (len(s) + n - 1) / n
	for i := 0; i < len(s); i += step {
		end := i + step
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "platform-api base URL")
	token := flag.String("token", os.Getenv("IOREC_TOKEN"), "project or collector token")
	runID := flag.String("run", "", "run id (default: generated)")
	batchSize := flag.Int("batch", 25, "events per batch")
	dropBatch := flag.Int("drop-batch", -1, "index of a batch to withhold until the end (tests out-of-order durable_seq)")
	reorder := flag.Bool("reorder", false, "upload batches in reverse order")
	corrupt := flag.Int("corrupt-hash", -1, "index of a batch to upload with a corrupted sha256 first")
	conflict := flag.Int("conflict", -1, "index of a batch to re-upload with different content (expects 409)")
	disconnectAfter := flag.Int("disconnect-after", -1, "stop after N batches without sealing (simulates crash); rerun with same --run and --resume")
	resume := flag.Bool("resume", false, "resume: skip batches the server already has")
	outDir := flag.String("out", "", "write run/ directory (events.jsonl, blobs/, manifest.json) instead of uploading")
	seal := flag.Bool("seal", true, "seal the recording at the end")
	register := flag.Bool("register", true, "register as a collector first (requires project token)")
	pid := flag.Int("pid", 4242, "pid of the fake agent")
	noHooks := flag.Bool("no-hooks", false, "pure proxy capture: drop hook events and explicit inference ids (tests prefix_chain inference)")
	flag.Parse()
	if *runID == "" {
		*runID = fmt.Sprintf("run_%s_%04x", time.Now().UTC().Format("20060102T150405"), rand.Intn(0xffff))
	}
	g := scenario(*runID, *pid)
	if *noHooks {
		var kept []protocol.Event
		var seq int64
		for _, e := range g.events {
			if e.Source == "hook" {
				continue
			}
			e.IDs.InferenceID, e.IDs.AgentSessionID, e.IDs.TurnID, e.IDs.ParentSpanID = "", "", "", ""
			seq++
			e.Seq = seq
			kept = append(kept, e)
		}
		g.events, g.seq = kept, seq
	}
	if *outDir != "" {
		writeRunDir(*outDir, g)
		return
	}
	if *token == "" {
		log.Fatal("token required (--token or IOREC_TOKEN)")
	}
	c := &client{api: *api, token: *token, http: &http.Client{Timeout: 60 * time.Second}}
	if *register {
		caps, _ := json.Marshal(json.RawMessage(mustJSON(g.events[1].Payload)))
		var resp struct {
			CollectorID  string `json:"collector_id"`
			SessionToken string `json:"session_token"`
		}
		if err := c.post("/v1/collectors:register", map[string]any{"name": "fake-collector", "version": "iorec 0.0.0-fake", "hostname": "localhost", "os": "linux/amd64", "capabilities": json.RawMessage(caps)}, &resp); err != nil {
			log.Fatalf("register: %v", err)
		}
		log.Printf("registered collector %s", resp.CollectorID)
		c.token = resp.SessionToken
		c.collectorID = resp.CollectorID
	}
	if err := c.post("/v1/recordings", map[string]any{"recording_id": g.rec, "capture_run_id": g.run, "segment_no": 0, "schema_version": 1, "run": map[string]any{"command": "hermes", "agent_kind": "hermes", "agent_version": "0.16.0", "started_at": g.events[0].WallTime}}, nil); err != nil {
		log.Fatalf("create recording: %v", err)
	}
	// upload blobs first
	for h, b := range g.blobs {
		if err := c.putBlob(h, b); err != nil {
			log.Fatalf("blob %s: %v", h, err)
		}
	}
	// batches
	type batch struct {
		hdr  protocol.BatchHeader
		comp []byte
		evs  []protocol.Event
	}
	var batches []batch
	for i := 0; i < len(g.events); i += *batchSize {
		end := i + *batchSize
		if end > len(g.events) {
			end = len(g.events)
		}
		evs := g.events[i:end]
		var refs []protocol.BlobRef
		for _, e := range evs {
			if e.PayloadRef != nil {
				refs = append(refs, protocol.BlobRef{SHA256: strings.TrimPrefix(e.PayloadRef.SHA256, "sha256:"), Size: e.PayloadRef.Size})
			}
		}
		hdr, comp, err := protocol.EncodeBatch(evs, refs)
		if err != nil {
			log.Fatal(err)
		}
		batches = append(batches, batch{hdr, comp, evs})
	}
	order := make([]int, len(batches))
	for i := range order {
		order[i] = i
	}
	if *reorder {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}
	var durable int64
	if *resume {
		var rec struct {
			DurableSeq int64 `json:"durable_seq"`
		}
		if err := c.get("/v1/recordings/"+urlEsc(g.rec), &rec); err != nil {
			log.Fatalf("resume: %v", err)
		}
		durable = rec.DurableSeq
		log.Printf("resuming from durable_seq=%d", durable)
	}
	sent := 0
	var withheld *batch
	for _, idx := range order {
		b := batches[idx]
		if *resume && b.hdr.LastSeq <= durable {
			continue
		}
		if idx == *dropBatch {
			bb := b
			withheld = &bb
			log.Printf("withholding batch %d [%d,%d]", idx, b.hdr.FirstSeq, b.hdr.LastSeq)
			continue
		}
		if idx == *corrupt {
			bad := b.hdr
			bad.SHA256 = strings.Repeat("0", 64)
			_, code, err := c.upload(g.rec, bad, b.comp)
			log.Printf("corrupt upload -> %d %v", code, err)
		}
		res, code, err := c.upload(g.rec, b.hdr, b.comp)
		if err != nil {
			log.Fatalf("batch %d: %d %v", idx, code, err)
		}
		log.Printf("batch %d [%d,%d] -> durable_seq=%d", idx, b.hdr.FirstSeq, b.hdr.LastSeq, res.DurableSeq)
		if idx == *conflict {
			alt := append([]protocol.Event(nil), b.evs...)
			alt[0].Payload = json.RawMessage(`{"tampered":true}`)
			h2, c2, _ := protocol.EncodeBatch(alt, nil)
			_, code, err := c.upload(g.rec, h2, c2)
			log.Printf("conflict re-upload -> %d %v", code, err)
		}
		sent++
		if *disconnectAfter >= 0 && sent >= *disconnectAfter {
			log.Printf("simulated disconnect after %d batches", sent)
			return
		}
	}
	if withheld != nil {
		res, _, err := c.upload(g.rec, withheld.hdr, withheld.comp)
		if err != nil {
			log.Fatalf("withheld batch: %v", err)
		}
		log.Printf("withheld batch delivered -> durable_seq=%d", res.DurableSeq)
	}
	if *seal {
		manifest := g.events[len(g.events)-1].Payload
		if err := c.post("/v1/recordings/"+urlEsc(g.rec)+":seal", map[string]any{"final_seq": g.seq, "manifest": json.RawMessage(manifest)}, nil); err != nil {
			log.Fatalf("seal: %v", err)
		}
		log.Printf("sealed %s at seq %d", g.rec, g.seq)
	}
	if c.collectorID != "" {
		_ = c.post("/v1/collectors/"+c.collectorID+":heartbeat", map[string]any{"status": "healthy", "active_runs": 0, "acked_lag_seconds": 0, "config_version": 0}, nil)
	}
	fmt.Println(g.rec)
}

func mustJSON(b json.RawMessage) []byte { return b }

func urlEsc(s string) string { return strings.ReplaceAll(s, "#", "%23") }

type client struct {
	api, token, collectorID string
	http                    *http.Client
}

func (c *client) do(req *http.Request, out any) (int, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s", strings.TrimSpace(string(body)))
	}
	if out != nil && len(body) > 0 {
		return resp.StatusCode, json.Unmarshal(body, out)
	}
	return resp.StatusCode, nil
}

func (c *client) post(path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.api+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	_, err := c.do(req, out)
	return err
}

func (c *client) get(path string, out any) error {
	req, _ := http.NewRequest("GET", c.api+path, nil)
	_, err := c.do(req, out)
	return err
}

func (c *client) putBlob(sha string, b []byte) error {
	req, _ := http.NewRequest("HEAD", c.api+"/v1/blobs/"+sha, nil)
	if code, _ := c.do(req, nil); code == 200 {
		return nil
	}
	req, _ = http.NewRequest("PUT", c.api+"/v1/blobs/"+sha, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	_, err := c.do(req, nil)
	return err
}

type ack struct {
	DurableSeq   int64    `json:"durable_seq"`
	State        string   `json:"state"`
	MissingBlobs []string `json:"missing_blobs"`
}

func (c *client) upload(rec string, hdr protocol.BatchHeader, comp []byte) (*ack, int, error) {
	var body bytes.Buffer
	if err := protocol.WriteBatchBody(&body, hdr, comp); err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequest("POST", c.api+"/v1/recordings/"+urlEsc(rec)+"/batches", &body)
	req.Header.Set("Content-Type", protocol.ContentTypeBatch)
	req.Header.Set("Idempotency-Key", hdr.BatchID)
	req.Header.Set("X-Batch-SHA256", hdr.SHA256)
	var a ack
	code, err := c.do(req, &a)
	if err != nil {
		return nil, code, err
	}
	return &a, code, nil
}

func writeRunDir(dir string, g *gen) {
	if err := os.MkdirAll(dir+"/blobs", 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(dir + "/events.jsonl")
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range g.events {
		b, _ := json.Marshal(e)
		f.Write(b)
		f.Write([]byte("\n"))
	}
	f.Close()
	for h, b := range g.blobs {
		_ = os.WriteFile(dir+"/blobs/sha256-"+h, b, 0o644)
	}
	m := map[string]any{"run_id": g.run, "recording_id": g.rec, "final_seq": g.seq, "claim": "best-effort"}
	mb, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(dir+"/manifest.json", mb, 0o644)
	fmt.Printf("wrote %d events to %s\n", len(g.events), dir)
}
