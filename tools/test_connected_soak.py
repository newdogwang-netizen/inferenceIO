#!/usr/bin/env python3

from __future__ import annotations

import io
import json
import subprocess
import unittest
import urllib.error
from unittest import mock

import connected_soak


class ConnectedSoakTests(unittest.TestCase):
    def test_subprocess_failure_diagnostics_do_not_publish_arguments_or_stderr(self) -> None:
        error = subprocess.CalledProcessError(
            1, ["/private/binary", "inspect", "sensitive-run", "--key-file", "secret"],
            stderr="iorec: storage I/O failed: No such file or directory (os error 2): PRIVATE",
        )
        result = connected_soak.failure_diagnostics(error)
        self.assertEqual(result["category"], "storage_entry_not_found")
        self.assertEqual(result["iorec_subcommand"], "inspect")
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(len(result["stderr_sha256"]), 64)
        encoded = json.dumps(result)
        for secret in ("PRIVATE", "secret", "sensitive-run", "/private"):
            self.assertNotIn(secret, encoded)

    def test_unknown_failure_diagnostics_fail_closed_without_guessing(self) -> None:
        result = connected_soak.failure_diagnostics(
            subprocess.CalledProcessError(7, ["binary", "private-command"], stderr=b"secret"))
        self.assertEqual(result["category"], "unclassified")
        self.assertNotIn("iorec_subcommand", result)
        self.assertEqual(connected_soak.failure_diagnostics(ValueError("secret")),
                         {"kind": "ValueError"})

    def test_compose_and_provider_secrets_do_not_reach_workload_children(self) -> None:
        with mock.patch.dict("os.environ", {"IOREC_USER_TOKENS": "private", "POSTGRES_PASSWORD": "private",
                                           "OPENAI_API_KEY": "private", "PATH": "/usr/bin"}, clear=True):
            env = connected_soak.workload_environment()
        self.assertEqual(set(env), {"PATH", "LANG", "LC_ALL", "TZ"})
        self.assertEqual(env["PATH"], "/usr/bin")

    def test_api_json_retries_rate_limit_with_bounded_retry_after(self) -> None:
        limited = urllib.error.HTTPError(
            "http://127.0.0.1:1/v1/overview",
            429,
            "Too Many Requests",
            {"Retry-After": "999999"},
            io.BytesIO(b"{}"),
        )
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {"Content-Length": "2"}
        response.read.return_value = json.dumps({}).encode()
        with (
            mock.patch(
                "connected_soak.urllib.request.urlopen",
                side_effect=[limited, response],
            ) as urlopen,
            mock.patch("connected_soak.time.sleep") as sleep,
        ):
            self.assertEqual(
                connected_soak.api_json(
                    "http://127.0.0.1:1", "/v1/overview", "private-token"
                ),
                {},
            )
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(
            connected_soak.MAX_API_RETRY_AFTER_SECONDS
        )

    def test_runtime_provenance_binds_images_and_hardening(self) -> None:
        def container(service: str, index: int = 1) -> dict[str, object]:
            application = service != "postgres"
            published = service in {"platform-api", "web-console"}
            return {
                "name": f"qualification-{service}-{index}",
                "service": service,
                "container_id": f"container-{service}-{index}",
                "image_id": f"sha256:image-{service}",
                "image_reference": f"iorec/{service}:candidate",
                "state": "running",
                "health": "healthy" if service == "web-console" else None,
                "user": "65532:65532" if application else "",
                "read_only_rootfs": application,
                "cap_drop": ["ALL"] if application else [],
                "security_opt": ["no-new-privileges:true"] if application else [],
                "logging": {
                    "driver": "json-file",
                    "max_size": "20m",
                    "max_file": "5",
                },
                "port_bindings": (
                    [{"container_port": "8080/tcp", "host_ips": ["127.0.0.1"]}]
                    if published
                    else []
                ),
            }

        snapshot = {
            "captured_at": "2026-09-16T00:00:00+00:00",
            "compose_config_sha256": "sha256:config",
            "compose_files": [{"path": "/compose.yaml", "sha256": "sha256:file"}],
            "containers": [
                container("platform-api"),
                container("pipeline-worker", 1),
                container("pipeline-worker", 2),
                container("web-console"),
                container("postgres"),
            ],
        }
        result = connected_soak.runtime_provenance(snapshot, snapshot)
        self.assertTrue(result["passed"])
        snapshot["containers"][0]["read_only_rootfs"] = False
        self.assertFalse(connected_soak.runtime_provenance(snapshot, snapshot)["passed"])

    def test_spool_chain_requires_contiguous_sealed_acknowledged_segments(self) -> None:
        states = [
            {
                "run_id": "run-1",
                "recording_id": "run-1#0000",
                "acked_seq": 2,
                "sealed": True,
                "collector_id": "collector-1",
                "batches": [{"first_seq": 1, "last_seq": 2, "event_count": 2}],
            },
            {
                "run_id": "run-1",
                "recording_id": "run-1#0001",
                "acked_seq": 4,
                "sealed": True,
                "collector_id": "collector-1",
                "batches": [{"first_seq": 3, "last_seq": 4, "event_count": 2}],
            },
        ]
        self.assertTrue(connected_soak.validate_spool_chain(states, "run-1", 4)["passed"])
        states[1]["batches"][0]["first_seq"] = 4
        self.assertFalse(connected_soak.validate_spool_chain(states, "run-1", 4)["passed"])

    def test_short_report_cannot_be_release_qualified(self) -> None:
        report = {
            "passed": True,
            "configuration": {"collectors": 20},
            "measurement": {
                "minimum_recorder_seconds": 17_999.9,
                "orchestrator_seconds": 18_000.0,
            },
            "faults": {
                "platform_unavailable_observed": True,
                "local_recording_advanced": {str(index): True for index in range(20)},
                "collector_identity_stable": {str(index): True for index in range(20)},
                "worker_restart_passed": True,
            },
            "checks": {
                "deletion_propagation": True,
                "platform_runtime_provenance": True,
            },
        }
        self.assertFalse(connected_soak.report_qualifies(report))
        report["measurement"]["minimum_recorder_seconds"] = 18_000.0
        self.assertTrue(connected_soak.report_qualifies(report))
        report["configuration"]["workload"] = "mixed-websocket"
        self.assertFalse(connected_soak.report_qualifies(report))
        report["checks"].update(websocket_projection=True, websocket_cross_segment_connections=True, artifacts_unchanged=True)
        report["websocket_projections"] = [{} for _ in range(10)]
        self.assertTrue(connected_soak.report_qualifies(report))
        report["checks"]["artifacts_unchanged"] = False
        self.assertFalse(connected_soak.report_qualifies(report))


if __name__ == "__main__":
    unittest.main()
