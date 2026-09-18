import copy
import hashlib
import unittest
from urllib.parse import unquote, urlsplit, parse_qs

import websocket_soak_validation as validation


def fixture():
    rows = [{"id": "connection", "entity_kind": "websocket_connection"}]
    details = {"connection": {"terminal_state": "completed", "projection": {"unresolved_messages": 0}}}
    ledgers, pages, blobs = [], {"connection": []}, {}
    inferences = {}
    for index in range(2):
        call = f"call-{index}"
        request_id, response_id = f"q-{index}", f"resp-{index}"
        previous = "resp-0" if index else None
        usage = {"input_tokens": 100+index, "output_tokens": 10+index}
        text = f"text-{index} 中文🙂"
        request = {"type": "response.create", "event_id": request_id}
        if previous:
            request["previous_response_id"] = previous
        response = {"id": response_id, "status": "completed", "usage": usage}
        normalized = {"response_text": text, "messages": [], "response_tool_calls": []}
        seq = index*3+1
        events = [{"event": "websocket_frame", "seq": seq+offset, "recording_id": f"run#{index}",
                   "call_attempt_id": call, "payload_sha256": f"blob-{index}-{offset}"} for offset in range(2)]
        blobs[events[0]["payload_sha256"]] = request
        blobs[events[1]["payload_sha256"]] = {"type": "response.completed", "response": response}
        details[call] = {"id": call, "projection": {"request_event_id": request_id, "response_id": response_id,
                         "outcome": "completed", "capture_state": "observed_messages_verified"},
                         "normalized": normalized, "response_text": text, "usage": usage,
                         "inference_id": f"inference-{index}", "request_body": request, "response_body": response,
                         "evidence_refs": [{"recording_id": f"run#{index}", "first_seq": seq, "last_seq": seq+1}]}
        inferences[f"inference-{index}"] = {"normalized": normalized, "usage": usage, "server_state": "resolved"}
        rows.append({"id": call, "entity_kind": "websocket_call"})
        pages[call] = events
        pages["connection"].extend(copy.deepcopy(events))
        ledgers.append({"index": index, "request_id": request_id, "response_id": response_id,
                        "request_sha256": validation.digest(request), "response_sha256": validation.digest(response),
                        "previous_response_id": previous, "input_tokens": 100+index, "output_tokens": 10+index,
                        "response_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                        "tools": 0, "tool_results": 0, "server_messages": 1})
    pages["connection"].insert(2, {"event": "websocket_frame", "seq": 3, "recording_id": "run#0", "assignment_reason": "connection_control"})
    for seq, direction in [(6, "client_to_upstream"), (7, "upstream_to_client")]:
        pages["connection"].append({"event": "websocket_frame", "seq": seq, "recording_id": "run#1",
                                    "assignment_reason": "connection_control", "direction": direction, "payload": {"opcode": "close"}})
    client = {"expected_calls": ledgers, "successes": 2, "transport_attempts": 1}
    def read(url):
        parsed = urlsplit(url)
        parts = [unquote(item) for item in parsed.path.split("/")]
        if parsed.path == "/v1/attempts":
            return {"items": rows}
        if parts[-1] == "events":
            after = int(parse_qs(parsed.query)["after_seq"][0])
            all_events = pages[parts[-2]]
            # Exercise actual continuation through multiple bounded pages.
            remaining = [event for event in all_events if event["seq"] > after]
            items = remaining[:2]
            return {"items": items, "has_more": len(remaining) > 2,
                    "next_after_seq": items[-1]["seq"] if items else None, "total": len(all_events)}
        return {"attempts": details, "inferences": inferences, "blobs": blobs}[parts[2]][parts[3]]
    return read, client, details, pages, inferences


class ReconciliationTests(unittest.TestCase):
    def test_pagination_and_cross_segment_connection(self):
        read, client, *_ = fixture()
        report = validation.verify(read, "run", client)
        self.assertTrue(report["passed"], report)
        self.assertEqual((report["calls"], report["messages"], report["connections_crossing_segments"]), (2, 7, 1))

    def test_fails_closed_on_wrong_projection(self):
        for name, mutate, error in [
            ("text", lambda details, pages, inf: details["call-0"]["normalized"].update(response_text="corrupt"), "response_text_digest_mismatch"),
            ("terminal", lambda details, pages, inf: details["call-0"]["projection"].update(outcome="failed"), "model_outcome_mismatch"),
            ("usage", lambda details, pages, inf: details["call-0"]["usage"].update(input_tokens=999), "usage_mismatch"),
            ("refs", lambda details, pages, inf: details["call-0"].update(evidence_refs=[]), "missing_exact_evidence_reference"),
            ("owner", lambda details, pages, inf: pages["connection"][0].update(call_attempt_id="call-1"), "message_owner_mismatch"),
            ("truncated", lambda details, pages, inf: pages["call-0"][0].update(raw_truncated=True), "truncated_raw_message"),
            ("state", lambda details, pages, inf: inf["inference-1"].update(server_state="unresolved"), "previous_response_link_unresolved"),
            ("close", lambda details, pages, inf: pages["connection"].pop(), "missing_bidirectional_close_evidence"),
        ]:
            with self.subTest(name=name):
                read, client, details, pages, inferences = fixture()
                mutate(details, pages, inferences)
                report = validation.verify(read, "run", client)
                self.assertFalse(report["passed"])
                self.assertIn(error, report["errors"])

    def test_cursor_does_not_advance_cannot_be_accepted(self):
        read, client, *_ = fixture()
        def corrupt(url):
            response = read(url)
            if "/events?" in url:
                response["next_after_seq"] = 0
            return response
        with self.assertRaisesRegex(ValueError, "invalid_fixture_evidence_cursor"):
            validation.verify(corrupt, "run", client)


if __name__ == "__main__":
    unittest.main()
