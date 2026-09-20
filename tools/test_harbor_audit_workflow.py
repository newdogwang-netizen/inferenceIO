from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import harbor_audit_workflow as workflow


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.key = self.base / "key"
        self.key.write_bytes(bytes(range(32)))
        self.key.chmod(0o600)
        self.binary = self.base / "iorec"
        self.binary.write_bytes(b"binary fixture")
        self.trial = self.base / "task__trial"
        self.run = self.trial / "agent/iorec-runs/run-test"
        self.run.mkdir(parents=True)
        workflow.atomic_json(self.run / "manifest.json", {"run_id": "run-test", "status": "finished", "storage": {"encryption": {"algorithm": "fixture"}}})
        (self.run / "events.jsonl").write_bytes(b"encrypted-fixture")
        workflow.atomic_json(self.trial / "result.json", {"finished_at": "2026-09-18T00:00:00Z", "task_name": "task",
            "agent_info": {"name": "codex", "version": "test", "model_info": {"provider": "test", "name": "model"}},
            "agent_result": {"cost_usd": 0.25}, "verifier_result": {"rewards": {"reward": 0}}})

    def args(self):
        return workflow.parser().parse_args(["--work-dir", str(self.base / "work"), "--from-trial", str(self.trial),
            "--key-file", str(self.key), "--iorec", str(self.binary), "--wait-seconds", "1"])

    def test_loopback_only_no_redirect_or_proxy_origins(self):
        self.assertEqual(workflow.local_url("http://localhost:8088/"), "http://127.0.0.1:8088")
        for value in ["http://example.com", "https://127.0.0.1", "http://127.0.0.1@evil", "http://127.0.0.1/?token=secret", "http://127.0.0.1/#fragment", "http://127.0.0.1/path", "file:///tmp/x"]:
            with self.subTest(value=value), self.assertRaises(workflow.Failure):
                workflow.local_url(value)

    def test_benchmark_zero_reward_not_capture_failure(self):
        result, provenance = workflow.benchmark_from_trial(self.trial)
        self.assertEqual(result["reward"], 0)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(provenance["reported_cost_usd"], 0.25)
        self.assertEqual(result["artifact_sha256"], workflow.digest(self.trial / "result.json"))

    def test_dominant_measurement_requires_a_clear_fourfold_lead(self):
        primary = {"invocation_id": "a", "wall_seconds": 40.0}
        auxiliary = {"invocation_id": "b", "wall_seconds": 10.0}
        selected, retained = workflow.dominant_measurement([auxiliary, primary])
        self.assertIs(selected, primary)
        self.assertEqual(retained, [auxiliary])
        with self.assertRaisesRegex(workflow.Failure, "without_unique_dominant"):
            workflow.dominant_measurement([primary, {**auxiliary, "wall_seconds": 10.01}])

    def test_measurement_capture_pairing_rejects_ambiguous_times(self):
        trial = self.base / "ambiguous-trial"
        captures = trial / "agent/iorec-runs"
        started = "2026-09-20T12:00:00+00:00"
        for name in ("run-a", "run-b"):
            run = captures / name
            run.mkdir(parents=True)
            workflow.atomic_json(run / "manifest.json", {
                "run_id": name, "status": "finished", "started_at": started, "exit_code": 0,
                "storage": {"encryption": {"algorithm": "fixture"}},
            })
        measurements = [
            {"invocation_id": "a", "wall_seconds": 40.0, "started_at": started, "exit_code": 0},
            {"invocation_id": "b", "wall_seconds": 1.0, "started_at": started, "exit_code": 0},
        ]
        with self.assertRaisesRegex(workflow.Failure, "pairing_ambiguous"):
            workflow.pair_measurements_and_captures(trial, measurements)

    def test_unfinished_trial_not_retried(self):
        workflow.atomic_json(self.trial / "result.json", {"finished_at": None})
        with self.assertRaisesRegex(workflow.Failure, "trial_not_finished_no_restart"):
            workflow.benchmark_from_trial(self.trial)

    def test_workspace_refuses_unrelated_contents_and_symlink(self):
        unrelated = self.base / "unrelated"
        unrelated.mkdir(mode=0o700)
        (unrelated / "keep").write_text("user data")
        with self.assertRaises(workflow.Failure):
            with workflow.Workspace(unrelated):
                pass
        self.assertTrue((unrelated / "keep").exists())
        link = self.base / "link"
        link.symlink_to(unrelated, target_is_directory=True)
        with self.assertRaises(workflow.Failure):
            with workflow.Workspace(link):
                pass

    def test_lock_inherited_by_live_child_prevents_cleanup_or_restart(self):
        args = self.args()
        with workflow.Workspace(args.work_dir) as work:
            workflow.atomic_json(work.path / "state.json", {"schema_version": 1})
            child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE,
                                     pass_fds=(work.lock.fileno(),))
            self.addCleanup(lambda: child.poll() is None and child.kill())
        try:
            with self.assertRaisesRegex(workflow.Failure, "still_running"):
                with workflow.Workspace(args.work_dir):
                    pass
        finally:
            child.communicate(timeout=5)
        with workflow.Workspace(args.work_dir):
            pass

    def test_interrupted_scratch_cleanup_is_scoped(self):
        args = self.args()
        script = """
import os, signal, sys
from pathlib import Path
from harbor_audit_workflow import Workspace, atomic_json
work = Workspace(Path(sys.argv[1])).__enter__()
atomic_json(work.path / 'state.json', {'schema_version': 1, 'stages': {}})
(work.path / 'keep').write_text('encrypted evidence placeholder')
(work.path / 'scratch').mkdir(mode=0o700)
(work.path / 'scratch/private.tar').write_text('sensitive staging fixture')
os.kill(os.getpid(), signal.SIGKILL)
"""
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
        crashed = subprocess.run([sys.executable, "-c", script, str(args.work_dir)], env=env, timeout=10)
        self.assertEqual(crashed.returncode, -9)
        self.assertTrue((args.work_dir / "scratch/private.tar").exists())
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=workflow.Failure("stop_after_crash_cleanup")):
                with self.assertRaises(workflow.Failure):
                    w.run()
            self.assertFalse((work.path / "scratch").exists())
            self.assertTrue((work.path / "keep").exists())

    @mock.patch.object(workflow, "api_request")
    def test_import_error_cleans_plaintext_and_retry_is_idempotent(self, request):
        args = self.args()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            w.state["run_path"] = str(self.run)
            w.state["source_identity"] = {"run_id": "run-test"}
            def export(*_, **__):
                scratch = work.path / "scratch"
                scratch.mkdir(mode=0o700)
                bundle = scratch / "bundle.tar"
                bundle.write_bytes(b"payload and TLS secrets")
                bundle.chmod(0o600)
            with mock.patch.object(w, "command", side_effect=export):
                request.side_effect = workflow.Failure("platform_http_503")
                with self.assertRaises(workflow.Failure):
                    w.import_run()
                self.assertFalse((work.path / "scratch").exists())
                request.side_effect = None
                request.return_value = {"capture_run_id": "run-test", "recording_id": "run-test#0000", "sealed": True}
                self.assertTrue(w.import_run()["sealed"])
                self.assertFalse((work.path / "scratch").exists())
                self.assertTrue((self.run / "events.jsonl").exists())
                self.assertTrue(self.key.exists())

    def test_launch_intent_never_automatically_resubmits(self):
        args = self.args()
        args.task, args.from_trial, args.model = self.base / "task", None, "test/model"
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            w.state["launch_intent"] = {"at": "prior", "pid": 999999}
            with mock.patch.object(subprocess, "Popen") as launch:
                with self.assertRaisesRegex(workflow.Failure, "no_automatic_agent_retry"):
                    w.record()
                launch.assert_not_called()

    @mock.patch.object(workflow, "api_request", return_value={"ok": True})
    def test_changed_inputs_cannot_reuse_workflow(self, _):
        args = self.args()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            w.preflight()
            args.agent_timeout += 1
            with self.assertRaisesRegex(workflow.Failure, "inputs_changed"):
                w.preflight()

    def test_fresh_harbor_configuration_has_bounded_no_retry_agent(self):
        args = self.args()
        args.task, args.model = self.base / "task", "test/model"
        config = workflow.harbor_config(args, args.work_dir)
        self.assertEqual(config["retry"]["max_retries"], 0)
        self.assertEqual(config["n_attempts"], 1)
        self.assertEqual(config["agents"][0]["max_timeout_sec"], args.agent_timeout)
        self.assertEqual(config["n_concurrent_trials"], 1)

    def test_report_never_contains_untrusted_error_payload(self):
        args = self.args()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=RuntimeError("API_KEY=secret payload")):
                with self.assertRaises(RuntimeError):
                    w.run()
            report = (work.path / "report.json").read_text()
            self.assertNotIn("secret", report)
            self.assertNotIn("API_KEY", report)
            self.assertEqual(json.loads(report)["stages"]["preflight"]["error"], "RuntimeError")

    def test_revalidation_clears_stale_green_status_before_first_stage(self):
        args = self.args()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            w.state.update(status="completed", stages={"platform": {"status": "completed"}}, plaintext_staging_cleaned=True)
            w.publish_report()
            def preflight():
                current = workflow.read_json(work.path / "report.json")
                self.assertFalse(current["qualification_passed"])
                self.assertEqual(current["workflow_status"], "running")
                self.assertNotIn("platform", current["stages"])
                raise workflow.Failure("injected_preflight_failure")
            with mock.patch.object(w, "preflight", side_effect=preflight):
                with self.assertRaises(workflow.Failure):
                    w.run()

    @unittest.skipUnless(os.environ.get("IOREC_WORKFLOW_TEST_RUN"), "requires an explicitly supplied encrypted capture")
    def test_real_export_http503_cleanup(self):
        original = Path(os.environ["IOREC_WORKFLOW_TEST_RUN"])
        original_hash = workflow.digest(original / "manifest.json")
        class RejectImport(BaseHTTPRequestHandler):
            received = 0
            def do_POST(self):
                remaining = int(self.headers["Content-Length"])
                while remaining:
                    block = self.rfile.read(min(1 << 20, remaining))
                    if not block:
                        break
                    remaining -= len(block)
                    type(self).received += len(block)
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b'{"error":{"code":"injected_import_failure"}}')
            def log_message(self, *_):
                pass
        server = HTTPServer(("127.0.0.1", 0), RejectImport)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            args = self.args()
            args.api = f"http://127.0.0.1:{server.server_port}"
            args.key_file = Path(os.environ["IOREC_WORKFLOW_TEST_KEY"])
            args.iorec = Path(os.environ["IOREC_WORKFLOW_TEST_BIN"])
            with workflow.Workspace(args.work_dir) as work:
                w = workflow.Workflow(args, work)
                w.state["run_path"] = str(original)
                w.state["source_identity"] = {"run_id": workflow.read_json(original / "manifest.json")["run_id"]}
                with self.assertRaisesRegex(workflow.Failure, "platform_http_503"):
                    w.stage("import", w.import_run)
                self.assertGreater(RejectImport.received, 0)
                self.assertFalse((work.path / "scratch").exists())
                self.assertTrue(args.key_file.exists())
            self.assertEqual(workflow.digest(original / "manifest.json"), original_hash)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
