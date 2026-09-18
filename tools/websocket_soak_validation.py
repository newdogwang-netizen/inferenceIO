"""Read-only reconciliation against the independent fixture client's ledger.

This verifies application projection, not pcap/TLS wire completeness. Read
callbacks must enforce project authentication and bounded HTTP responses.
"""
import hashlib
import json
from urllib.parse import quote


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(read, run_id, client):
    errors = []
    expected = {row["request_id"]: row for row in client["expected_calls"]}
    def check(condition, code):
        if not condition:
            errors.append(code)
    def detail(kind, identifier):
        return read(f"/v1/{kind}/{quote(identifier, safe='')}"+("?view=normalized" if kind == "attempts" else ""))
    def events(identifier):
        result, after = [], 0
        for _ in range(100):
            page = read(f"/v1/attempts/{quote(identifier, safe='')}/events?limit=1000&after_seq={after}")
            items = page["items"]
            if items and (items[0]["seq"] <= after or any(a["seq"] >= b["seq"] for a,b in zip(items,items[1:]))):
                raise ValueError("non_monotonic_fixture_evidence")
            result.extend(items)
            if not page["has_more"]:
                check(len(result) == page["total"], "event_page_total_mismatch")
                return result
            if not items or page["next_after_seq"] != items[-1]["seq"]:
                raise ValueError("invalid_fixture_evidence_cursor")
            after = page["next_after_seq"]
        raise ValueError("fixture_evidence_page_limit")

    rows = read(f"/v1/attempts?capture_run_id={quote(run_id,safe='')}&limit=2000")["items"]
    check(len(rows) < 2000, "attempt_listing_would_be_truncated")
    parents = [row for row in rows if row.get("entity_kind") == "websocket_connection"]
    calls = [row for row in rows if row.get("entity_kind") == "websocket_call"]
    check(len(expected) == len(client["expected_calls"]) == client["successes"] == len(calls), "call_count_mismatch")
    check(len(parents) == client["transport_attempts"], "connection_count_mismatch")
    check(len(rows) == len(parents)+len(calls), "unexpected_attempt_kind")
    check(len(calls) > len(parents), "connection_reuse_not_exercised")
    seen_requests, seen_events, parent_frames = set(), set(), {}
    connections_crossing_segments = 0
    for row in parents:
        parent = detail("attempts", row["id"])
        check(parent.get("inference_id") is None and parent.get("usage") is None and parent.get("normalized") is None, "aggregate_call_fields_on_connection")
        check(parent.get("terminal_state") == "completed", "unclean_connection_terminal")
        check(parent.get("projection", {}).get("unresolved_messages") == 0, "unresolved_parent_messages")
        frames = [event for event in events(row["id"]) if event["event"] == "websocket_frame"]
        closes = [event for event in frames if (event.get("payload") or {}).get("opcode") == "close"]
        check(sorted(event.get("direction", "") for event in closes) == ["client_to_upstream", "upstream_to_client"], "missing_bidirectional_close_evidence")
        if len({event["recording_id"] for event in frames}) > 1:
            connections_crossing_segments += 1
        for event in frames:
            key = (event["recording_id"], event["seq"])
            check(key not in parent_frames, "duplicate_parent_event")
            parent_frames[key] = event
    input_tokens = output_tokens = tool_calls = tool_results = 0
    for row in calls:
        call = detail("attempts", row["id"])
        projection = call.get("projection") or {}
        request_id = projection.get("request_event_id")
        check(request_id not in seen_requests, "duplicate_call_request")
        seen_requests.add(request_id)
        wanted = expected.get(request_id)
        if not wanted:
            errors.append("unexpected_request_id")
            continue
        check(projection.get("response_id") == wanted["response_id"], "response_id_mismatch")
        check(projection.get("outcome") == "completed", "model_outcome_mismatch")
        check(projection.get("capture_state") == "observed_messages_verified", "capture_state_not_verified")
        normalized = call.get("normalized") or {}
        text = normalized.get("response_text", "")
        check(hashlib.sha256(text.encode()).hexdigest() == wanted["response_text_sha256"], "response_text_digest_mismatch")
        check(call.get("response_text") == text, "display_text_mismatch")
        usage = call.get("usage") or {}
        check(usage.get("input_tokens") == wanted["input_tokens"] and usage.get("output_tokens") == wanted["output_tokens"], "usage_mismatch")
        input_tokens += usage.get("input_tokens", 0)
        output_tokens += usage.get("output_tokens", 0)
        tools = normalized.get("response_tool_calls") or []
        results = [message for message in normalized.get("messages", []) if message.get("role") == "tool"]
        tool_calls += len(tools)
        tool_results += len(results)
        check(len(tools) == wanted["tools"] and len(results) == wanted["tool_results"], "tool_count_mismatch")
        if tools:
            check(tools[0].get("arguments") == f"printf turn {wanted['index']}" and tools[0].get("id") == "tool-"+request_id and tools[0].get("name") == "fixture_exec", "tool_content_mismatch")
        if results:
            check(results[0].get("text") == f"fixture-result-{wanted['index']-1}", "tool_result_content_mismatch")
        if not call.get("inference_id"):
            errors.append("missing_logical_inference")
        else:
            inference = detail("inferences", call["inference_id"])
            check(inference.get("normalized") == normalized and inference.get("usage") == usage, "inference_projection_mismatch")
            if wanted["previous_response_id"]:
                check(inference.get("server_state") == "resolved", "previous_response_link_unresolved")
        messages = events(row["id"])
        check(len(messages) == wanted["server_messages"]+1, "call_message_count_mismatch")
        for event in messages:
            key = (event["recording_id"], event["seq"])
            check(key not in seen_events, "message_assigned_twice")
            seen_events.add(key)
            check(parent_frames.get(key, {}).get("call_attempt_id") == row["id"] == event.get("call_attempt_id"), "message_owner_mismatch")
            check(not event.get("raw_truncated"), "truncated_raw_message")
            check(any(ref["recording_id"] == event["recording_id"] and ref["first_seq"] <= event["seq"] <= ref["last_seq"] for ref in call.get("evidence_refs", [])), "missing_exact_evidence_reference")
        if messages:
            original_request = read("/v1/blobs/"+messages[0]["payload_sha256"])
            original_final = read("/v1/blobs/"+messages[-1]["payload_sha256"])
            check(original_request == call.get("request_body"), "request_body_not_equal_to_original")
            check(digest(original_request) == wanted["request_sha256"], "request_differs_from_client_sent_content")
            check(digest(original_final.get("response")) == wanted["response_sha256"], "response_differs_from_client_received_content")
            check(original_final.get("type") == "response.completed" and original_final.get("response") == call.get("response_body"), "terminal_snapshot_not_equal_to_original")
            check(original_final.get("response", {}).get("usage") == usage, "usage_not_equal_to_original")
            check(original_request.get("previous_response_id") == wanted["previous_response_id"], "request_state_reference_mismatch")
    check(seen_requests == set(expected), "missing_expected_call")
    controls = {key for key,event in parent_frames.items() if event.get("assignment_reason") == "connection_control"}
    check(not (controls & seen_events) and controls | seen_events == set(parent_frames), "message_accounting_gap")
    check(bool(controls), "control_messages_not_exercised")
    return {"capture_run_id": run_id, "passed": not errors, "errors": sorted(set(errors)),
            "calls": len(calls), "connections": len(parents), "messages": len(parent_frames), "control_messages": len(controls),
            "connections_crossing_segments": connections_crossing_segments,
            "close_handshakes": len(parents) if not any(error in errors for error in ("unclean_connection_terminal", "missing_bidirectional_close_evidence")) else None,
            "tool_calls": tool_calls, "tool_results": tool_results,
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "scope": "synthetic_websocket_application_projection_not_independent_wire_proof_or_real_agent_matrix"}
