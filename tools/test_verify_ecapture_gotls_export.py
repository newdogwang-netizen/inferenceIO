#!/usr/bin/python3
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify_ecapture_gotls_export.py")
SPEC = importlib.util.spec_from_file_location("verify_ecapture_gotls_export", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class GoTLSExportVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="iorec-gotls-verifier-")
        self.path = Path(self.directory.name) / "probe.jsonl"
        self.executable_sha256 = "sha256:" + "a" * 64

    def tearDown(self) -> None:
        self.directory.cleanup()

    @staticmethod
    def evidence(direction: str, payload: bytes, *, pid: int = 123) -> dict[str, object]:
        return {
            "type": "evidence",
            "schema_version": 2,
            "event": "tls_plaintext",
            "pid": pid,
            "tid": 124,
            "connection_id": "ecapture-" + "b" * 32,
            "direction": direction,
            "protocol": "tls",
            "media_type": "application/octet-stream",
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "confidence": 1.0,
        }

    def records(self) -> list[dict[str, object]]:
        body = b"TESTTEST"
        request = (
            b"POST /capture HTTP/1.1\r\nContent-Length: 8\r\n"
            b"X-Iorec-GoTLS-Marker: TEST\r\n\r\n" + body
        )
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n" + body
        )
        return [
            {
                "type": "ready",
                "schema_version": 2,
                "helper": "ecapture-bridge",
                "helper_version": "1.1.0",
                "upstream_version": "v2.6.0+test",
                "target_executable_sha256": self.executable_sha256,
                "filter_scope": "cgroup",
                "target_cgroup": "/sys/fs/cgroup/test",
                "capabilities": ["tls_plaintext", "go_tls_plaintext"],
                "target_pid": 123,
            },
            self.evidence("write", request),
            self.evidence("read", response),
            {
                "type": "final",
                "schema_version": 2,
                "captured_events": 2,
                "dropped_events": 0,
                "probe_hits": 2,
                "complete": True,
            },
        ]

    def write(self, records: list[dict[str, object]]) -> None:
        self.path.write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
            encoding="utf-8",
        )

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            export=self.path,
            marker="TEST",
            body_bytes=8,
            requests=1,
            executable_sha256=self.executable_sha256,
            helper_version="1.1.0",
            upstream_version="v2.6.0+test",
        )

    def test_accepts_exact_bidirectional_capture(self) -> None:
        self.write(self.records())
        result = verifier.verify(self.args())
        self.assertTrue(result["verified"])
        self.assertEqual(result["connections"], 1)
        self.assertEqual(result["captured_events"], 2)

    def test_rejects_payload_digest_disagreement(self) -> None:
        records = self.records()
        records[1]["payload_sha256"] = "sha256:" + "0" * 64
        self.write(records)
        with self.assertRaisesRegex(verifier.VerificationError, "digest disagrees"):
            verifier.verify(self.args())

    def test_rejects_event_outside_target_pid(self) -> None:
        records = self.records()
        records[2]["pid"] = 999
        self.write(records)
        with self.assertRaisesRegex(verifier.VerificationError, "escaped target PID"):
            verifier.verify(self.args())

    def test_rejects_unexpected_marker(self) -> None:
        records = self.records()
        request = base64.b64decode(records[1]["payload_base64"])
        request = request.replace(b"TEST", b"EVIL")
        records[1] = self.evidence("write", request)
        self.write(records)
        with self.assertRaisesRegex(verifier.VerificationError, "outside the expected task set"):
            verifier.verify(self.args())


if __name__ == "__main__":
    unittest.main()
