#!/usr/bin/python3
"""Verify a decrypted eCapture GoTLS protocol-v2 qualification export."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path


MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_RECORDS = 10_000
MAX_SEGMENT_BYTES = 16 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_records(path: Path) -> list[dict[str, object]]:
    require(path.is_file() and not path.is_symlink(), "export must be a regular non-symlink file")
    require(path.stat().st_size <= MAX_EXPORT_BYTES, "export exceeds verification size limit")
    records: list[dict[str, object]] = []
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            require(number <= MAX_RECORDS, "export exceeds verification record limit")
            require(len(raw) <= MAX_RECORD_BYTES, f"record {number} exceeds size limit")
            try:
                record = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise VerificationError(f"record {number} is not valid JSON") from exc
            require(isinstance(record, dict), f"record {number} is not an object")
            records.append(record)
    require(len(records) >= 3, "export must contain ready, evidence, and final records")
    return records


def decode_payload(record: dict[str, object], number: int) -> bytes:
    encoded = record.get("payload_base64")
    expected = record.get("payload_sha256")
    require(isinstance(encoded, str), f"evidence {number} has no base64 payload")
    require(isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None, f"evidence {number} has invalid SHA-256")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise VerificationError(f"evidence {number} has invalid base64") from exc
    require(0 < len(payload) <= MAX_SEGMENT_BYTES, f"evidence {number} payload is outside GoTLS segment bounds")
    actual = "sha256:" + hashlib.sha256(payload).hexdigest()
    require(actual == expected, f"evidence {number} payload digest disagrees")
    return payload


def parse_http_message(stream: bytes, *, response: bool) -> tuple[dict[bytes, bytes], bytes]:
    parts = stream.split(b"\r\n\r\n", 1)
    require(len(parts) == 2, "HTTP message has no header/body boundary")
    lines = parts[0].split(b"\r\n")
    expected_start = b"HTTP/1.1 200 OK" if response else b"POST /capture HTTP/1.1"
    require(lines and lines[0] == expected_start, "HTTP start line disagrees with qualification fixture")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        pair = line.split(b":", 1)
        require(len(pair) == 2 and pair[0], "HTTP header is malformed")
        name = pair[0].strip().lower()
        require(name not in headers, "duplicate HTTP header is ambiguous")
        headers[name] = pair[1].strip()
    body = parts[1]
    try:
        declared = int(headers[b"content-length"])
    except (KeyError, ValueError) as exc:
        raise VerificationError("HTTP Content-Length is missing or invalid") from exc
    require(declared == len(body), "HTTP Content-Length disagrees with reassembled body")
    return headers, body


def repeated_body(marker: bytes, size: int) -> bytes:
    return (marker * ((size + len(marker) - 1) // len(marker)))[:size]


def verify(args: argparse.Namespace) -> dict[str, object]:
    records = load_records(args.export)
    ready = records[0]
    final = records[-1]
    require(ready.get("type") == "ready" and ready.get("schema_version") == 2, "first record is not protocol-v2 ready")
    require(final.get("type") == "final" and final.get("schema_version") == 2, "last record is not protocol-v2 final")
    require(ready.get("helper") == "ecapture-bridge", "unexpected helper")
    require(ready.get("helper_version") == args.helper_version, "helper version disagrees")
    require(ready.get("upstream_version") == args.upstream_version, "upstream version disagrees")
    require(ready.get("target_executable_sha256") == args.executable_sha256, "target executable digest disagrees")
    require(ready.get("filter_scope") == "cgroup", "qualification did not use cgroup scope")
    target_cgroup = ready.get("target_cgroup")
    require(isinstance(target_cgroup, str) and target_cgroup.startswith("/sys/fs/cgroup/"), "target cgroup is invalid")
    capabilities = ready.get("capabilities")
    require(isinstance(capabilities, list) and "go_tls_plaintext" in capabilities, "GoTLS capability is absent")
    target_pid = ready.get("target_pid")
    require(isinstance(target_pid, int) and target_pid > 0, "target PID is invalid")

    streams: dict[str, dict[str, bytearray]] = {}
    evidence = records[1:-1]
    for number, record in enumerate(evidence, 2):
        require(record.get("type") == "evidence" and record.get("schema_version") == 2, f"record {number} is not evidence")
        require(record.get("event") == "tls_plaintext", f"record {number} is not TLS plaintext")
        require(record.get("pid") == target_pid, f"record {number} escaped target PID binding")
        require(record.get("protocol") == "tls", f"record {number} protocol is not TLS")
        require(record.get("media_type") == "application/octet-stream", f"record {number} media type disagrees")
        require(record.get("confidence") == 1.0, f"record {number} confidence disagrees")
        connection = record.get("connection_id")
        direction = record.get("direction")
        require(isinstance(connection, str) and connection.startswith("ecapture-"), f"record {number} connection ID is invalid")
        require(direction in ("read", "write"), f"record {number} direction is invalid")
        pair = streams.setdefault(connection, {"read": bytearray(), "write": bytearray()})
        pair[direction].extend(decode_payload(record, number))

    require(len(streams) == args.requests, "captured connection count disagrees")
    expected_markers = {
        (args.marker if args.requests == 1 else f"{args.marker}-{index:02d}").encode("ascii")
        for index in range(args.requests)
    }
    observed_markers: set[bytes] = set()
    request_bytes = 0
    response_bytes = 0
    for pair in streams.values():
        request_headers, request_body = parse_http_message(bytes(pair["write"]), response=False)
        response_headers, response_body = parse_http_message(bytes(pair["read"]), response=True)
        marker = request_headers.get(b"x-iorec-gotls-marker")
        require(marker in expected_markers, "request marker is outside the expected task set")
        require(marker not in observed_markers, "request marker was captured more than once")
        require(len(request_body) == args.body_bytes, "request body length disagrees")
        require(request_body == repeated_body(marker, args.body_bytes), "request body bytes disagree")
        require(response_headers.get(b"content-type") == b"application/octet-stream", "response content type disagrees")
        require(response_body == request_body, "response body does not exactly match request body")
        observed_markers.add(marker)
        request_bytes += len(pair["write"])
        response_bytes += len(pair["read"])
    require(observed_markers == expected_markers, "expected marker set is incomplete")

    captured_events = final.get("captured_events")
    probe_hits = final.get("probe_hits")
    require(final.get("complete") is True, "helper final is incomplete")
    require(final.get("dropped_events") == 0, "helper reported dropped events")
    require(captured_events == len(evidence), "final captured-event count disagrees")
    require(probe_hits == len(evidence), "final probe-hit count disagrees")
    return {
        "schema_version": 1,
        "verified": True,
        "helper_version": ready["helper_version"],
        "upstream_version": ready["upstream_version"],
        "target_pid": target_pid,
        "target_executable_sha256": ready["target_executable_sha256"],
        "target_cgroup": target_cgroup,
        "connections": len(streams),
        "captured_events": len(evidence),
        "request_stream_bytes": request_bytes,
        "response_stream_bytes": response_bytes,
        "application_body_bytes_each_direction": args.requests * args.body_bytes,
        "payload_hashes_valid": True,
        "bidirectional_connection_pairing_valid": True,
        "expected_marker_set_complete": True,
        "unexpected_marker_rejected": True,
        "dropped_events": 0,
        "final_complete": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("export", type=Path)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--body-bytes", required=True, type=int)
    parser.add_argument("--requests", required=True, type=int)
    parser.add_argument("--executable-sha256", required=True)
    parser.add_argument("--helper-version", default="1.1.0")
    parser.add_argument("--upstream-version", required=True)
    args = parser.parse_args()
    if not args.marker.isascii() or not args.marker or len(args.marker) > 128:
        parser.error("--marker must be 1..128 ASCII characters")
    if not 1 <= args.body_bytes <= MAX_EXPORT_BYTES:
        parser.error("--body-bytes is outside verification bounds")
    if not 1 <= args.requests <= 64:
        parser.error("--requests is outside verification bounds")
    if SHA256_RE.fullmatch(args.executable_sha256) is None:
        parser.error("--executable-sha256 is invalid")
    return args


def main() -> int:
    try:
        result = verify(parse_args())
    except (OSError, VerificationError) as exc:
        print(f"GoTLS qualification verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
