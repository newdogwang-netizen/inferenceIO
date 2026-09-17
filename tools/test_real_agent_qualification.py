#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

import real_agent_qualification as qualification


class RealAgentQualificationTests(unittest.TestCase):
    def fixture(self) -> qualification.AgentRun:
        validation = {
            "manifest": {
                "run_id": "run-test",
                "status": "finished",
                "exit_code": 0,
                "coverage": {
                    "capture_drops": 0,
                    "unknown_egress": 0,
                    "unresolved_correlations": 0,
                },
                "counts": {
                    "events": 10,
                    "blobs": 4,
                    "logical_tasks": 1,
                    "logical_inferences": 1,
                    "transport_attempts": 1,
                    "completed_attempts": 1,
                    "incomplete_attempts": 0,
                },
            },
            "missing_blobs": 0,
            "corrupt_blobs": 0,
            "discarded_tail_bytes": 0,
            "integrity_verifier": {"passed": True},
        }
        audit = {
            "complete": True,
            "schema_version": 3,
            "completeness_boundary": "target-network-namespace-ip-transport",
            "payload_diff_passed": True,
            "missing_from_wire": 0,
            "extra_on_wire": 0,
            "ambiguous_signature_groups": 0,
            "proxy_attempts_eligible": 1,
            "matched_attempts": 1,
            "proxy_attempts_non_model_excluded": 0,
            "decoded_streams": 1,
            "pcap_records": 8,
            "gaps": [],
        }
        placeholder = pathlib.Path("/private/not-read-by-summary")
        return qualification.AgentRun(
            "gemini", placeholder, placeholder, validation, audit, placeholder
        )

    def test_exact_run_passes_every_summary_gate(self) -> None:
        summary = qualification.summarize_run(self.fixture())
        self.assertTrue(summary["passed"])
        self.assertTrue(all(summary["checks"].values()))

    def test_transport_gap_fails_summary(self) -> None:
        run = self.fixture()
        run.audit["missing_from_wire"] = 1
        self.assertFalse(qualification.summarize_run(run)["passed"])

    def test_agent_environment_does_not_inherit_host_secrets(self) -> None:
        marker = "IOREC_TEST_HOST_SECRET"
        previous = os.environ.get(marker)
        os.environ[marker] = "must-not-cross-boundary"
        try:
            with tempfile.TemporaryDirectory() as temporary:
                environment = qualification.agent_environment(
                    "codex", pathlib.Path(temporary)
                )
        finally:
            if previous is None:
                os.environ.pop(marker, None)
            else:
                os.environ[marker] = previous
        self.assertNotIn(marker, environment)
        self.assertEqual(environment["PATH"], qualification.QUALIFICATION_PATH)
        self.assertEqual(environment["OPENAI_API_KEY"], "iorec-controlled-provider-key")

    def test_input_artifact_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            iorec = root / "iorec"
            agent = root / "agent"
            node = root / "node"
            tshark = root / "tshark"
            iorec.write_bytes(b"candidate-one")
            agent.write_bytes(b"agent-one")
            node.write_bytes(b"node-one")
            tshark.write_bytes(b"tshark-one")
            artifacts = {
                "example": {
                    "canonical_executable": str(agent),
                    "sha256": qualification.sha256_file(agent),
                }
            }
            with (
                mock.patch.object(qualification, "NODE_PATH", node),
                mock.patch.object(qualification, "TSHARK_PATH", tshark),
            ):
                inputs = qualification.input_artifacts(iorec, artifacts)
                iorec.write_bytes(b"candidate-two")
                with self.assertRaisesRegex(RuntimeError, "iorec_release"):
                    qualification.verify_input_artifacts(inputs, iorec, artifacts)

                iorec.write_bytes(b"candidate-one")
                inputs = qualification.input_artifacts(iorec, artifacts)
                agent.write_bytes(b"agent-two")
                with self.assertRaisesRegex(RuntimeError, "agent:example"):
                    qualification.verify_input_artifacts(inputs, iorec, artifacts)

    def test_failed_report_replacement_restores_previous_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "report.json"
            output.write_text('{"old":true}\n', encoding="utf-8")
            with mock.patch.object(
                qualification.perf_harness,
                "write_report_atomic",
                side_effect=OSError("injected publication failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected publication failure"):
                    qualification.publish_report(output, {"new": True}, True)
            self.assertEqual(output.read_text(encoding="utf-8"), '{"old":true}\n')
            self.assertEqual(list(output.parent.glob("*.superseded-*.json")), [])

    def test_report_replacement_refuses_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            output = root / "report.json"
            output.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlink"):
                qualification.publish_report(output, {"new": True}, True)


if __name__ == "__main__":
    unittest.main()
