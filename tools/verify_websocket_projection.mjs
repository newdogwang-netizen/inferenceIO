#!/usr/bin/env node
// Read-only, payload-free qualification of one platform WebSocket projection.
// Usage: node tools/verify_websocket_projection.mjs API_BASE CONNECTION_ID
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const [base = "http://127.0.0.1:18080", connectionID] = process.argv.slice(2);
if (!connectionID) throw new Error("provide API_BASE and CONNECTION_ID");
const origin = new URL(base);
if (!["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname) || origin.username || origin.password) {
  throw new Error("this local-dev qualification tool requires a credential-free loopback API URL");
}
async function read(path) {
  const response = await fetch(new URL(path, origin), { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`API read failed with HTTP ${response.status}`);
  return response.json();
}
// Do not attach provider data to assertion errors or ordinary logs.
function check(condition, code) { if (!condition) throw new Error(code); }
function equal(a, b) { try { assert.deepEqual(a, b); return true; } catch { return false; } }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
function hash(value) { return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex"); }

async function allEvents(id) {
  const events = []; let after = 0;
  for (let pageIndex = 0; pageIndex < 1000; pageIndex++) {
    const page = await read(`/v1/attempts/${encodeURIComponent(id)}/events?limit=1000&after_seq=${after}`);
    for (const event of page.items) { check(event.seq > after, "non_monotonic_event_page"); after = event.seq; events.push(event); }
    if (!page.has_more) { check(events.length === page.total, "incomplete_event_pagination"); return events; }
    check(page.next_after_seq === after && page.items.length > 0, "invalid_event_cursor");
  }
  throw new Error("event_pagination_safety_limit");
}

const parent = await read(`/v1/attempts/${encodeURIComponent(connectionID)}?view=normalized`);
parent.events = await allEvents(connectionID);
check(parent.entity_kind === "websocket_connection", "parent_is_not_a_connection");
check(parent.normalized === null && parent.usage === null && parent.inference_id === null, "connection_contains_aggregate_call_fields");
const frames = parent.events.filter(e => e.event === "websocket_frame");
const seen = new Set(), usage = { input_tokens: 0, output_tokens: 0 };
const outcomes = {}, fingerprints = [];
let toolCalls = 0, toolResults = 0, terminalChecks = 0;
for (const row of parent.calls) {
  const call = await read(`/v1/attempts/${encodeURIComponent(row.id)}?view=normalized`);
  call.events = await allEvents(row.id);
  check(call.parent_connection.id === connectionID, "wrong_parent_connection");
  check(call.entity_kind === "websocket_call", "wrong_child_kind");
  const inference = await read(`/v1/inferences/${encodeURIComponent(call.inference_id)}`);
  check(equal(call.normalized, inference.normalized) && equal(call.usage, inference.usage), "inference_projection_differs");
  for (const event of call.events) {
    const key = `${event.recording_id}:${event.seq}`;
    check(!seen.has(key), "duplicate_message_assignment");
    seen.add(key);
    check(event.call_attempt_id === call.id, "event_owner_mismatch");
    check(call.evidence_refs.some(r => r.recording_id === event.recording_id && r.first_seq <= event.seq && r.last_seq >= event.seq), "missing_evidence_reference");
  }
  const request = await read(`/v1/blobs/${call.events[0].payload_sha256}`);
  check(request.type === "response.create" && equal(request, call.request_body), "request_not_equal_to_original");
  const outcome = call.projection.outcome;
  outcomes[outcome] = (outcomes[outcome] ?? 0) + 1;
  if (["completed", "failed", "incomplete", "cancelled"].includes(outcome)) {
    const terminal = await read(`/v1/blobs/${call.events.at(-1).payload_sha256}`);
    check(terminal.type === `response.${outcome}`, "terminal_event_mismatch");
    check(equal(terminal.response, call.response_body), "final_snapshot_mismatch");
    check(equal(terminal.response.usage ?? null, call.usage), "usage_not_equal_to_final_snapshot");
    const output = terminal.response.output ?? [];
    const text = output.filter(v => v.type === "message").flatMap(v => v.content ?? []).map(v => v.text ?? "").join("");
    check((call.normalized.response_text ?? "") === text, "response_text_mismatch");
    const tools = output.filter(v => ["function_call", "custom_tool_call"].includes(v.type));
    check(tools.length === (call.normalized.response_tool_calls ?? []).length, "tool_call_count_mismatch");
    for (const tool of tools) {
      const normalized = call.normalized.response_tool_calls.find(v => v.id === tool.call_id);
      check(normalized?.name === tool.name && equal(normalized.arguments, tool.type === "custom_tool_call" ? tool.input : tool.arguments), "tool_call_content_mismatch");
    }
    toolCalls += tools.length;
    terminalChecks++;
  }
  for (const result of (request.input ?? []).filter?.(v => ["custom_tool_call_output", "function_call_output"].includes(v.type)) ?? []) {
    check(call.normalized.messages.some(v => v.role === "tool" && v.tool_call_id === result.call_id && (typeof result.output !== "string" || v.text === result.output)), "tool_result_missing");
    toolResults++;
  }
  for (const key of Object.keys(usage)) usage[key] += call.usage?.[key] ?? 0;
  fingerprints.push({ id: call.id, normalized: call.normalized, projection: call.projection, evidence_refs: call.evidence_refs });
}
const controls = frames.filter(e => e.assignment_reason === "connection_control").length;
const unresolved = frames.filter(e => !e.call_attempt_id && e.assignment_reason !== "connection_control").length;
check(frames.length === seen.size + controls + unresolved, "message_accounting_does_not_balance");
check(unresolved === parent.projection.unresolved_messages, "unresolved_counter_mismatch");
check(parent.calls.length === parent.projection.calls, "call_counter_mismatch");
console.log(JSON.stringify({ schema_version: 1, passed: true, connection_id: connectionID,
  processor_version: parent.processor_version, calls: parent.calls.length, outcomes,
  messages: frames.length, assigned_messages: seen.size, control_messages: controls,
  unresolved_messages: unresolved, terminal_checks: terminalChecks, tool_calls: toolCalls,
  tool_results: toolResults, usage, projection_sha256: hash(fingerprints),
  transport_terminal: parent.terminal_state, transport_error_class: parent.error_class,
  close_diagnosis: parent.projection.close_diagnosis,
  scope: "application_call_projection_against_original_message_blobs_not_transport_qualification" }, null, 2));
