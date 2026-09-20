from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import harbor_audit_workflow as workflow
from harbor_input_provenance import measurement_definitions

measure = measurement_definitions()
SCRIPT = workflow.ROOT / "examples/harbor_audit_measure.py"


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.trial = self.root / "trial"
        self.output = self.trial / "agent/iorec-measurements"

    def command(self, code, mode="on", argv=()):
        return [sys.executable, "-I", "-B", str(SCRIPT), "--output", str(self.output),
                "--mode", mode, "--", sys.executable, "-c", code, *argv]

    def read(self, mode="on"):
        return measure.read_trial_measurement(self.trial, mode)

    def test_stdio_argv_exit_and_private_bounded_metrics(self):
        secret = "fake-credential-not-for-report"
        code = "import json,sys; print(json.dumps([sys.argv[1:],sys.stdin.read()])); print('stderr',file=sys.stderr); sys.exit(17)"
        argv = ["", "--", "$(false) '中文'\n", secret]
        result = subprocess.run(self.command(code, argv=argv), input="stdin\x00" + secret,
                                text=True, capture_output=True, timeout=10,
                                env={**os.environ, "FAKE_TEST_SECRET": secret})
        self.assertEqual(result.returncode, 17)
        self.assertEqual(json.loads(result.stdout), [argv, "stdin\x00" + secret])
        self.assertEqual(result.stderr, "stderr\n")
        report = self.read()
        self.assertEqual(report["exit_code"], 17)
        self.assertGreater(report["wall_seconds"], 0)
        self.assertGreater(report["max_rss_kib"], 0)
        self.assertNotIn(secret, json.dumps(report))
        for path in self.output.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertNotIn(secret, path.read_text())

    def test_cpu_and_rss_include_waited_child_scope(self):
        grandchild = "import time; x=bytearray(64*1024*1024); deadline=time.process_time()+0.15\nwhile time.process_time()<deadline: pass"
        code = "import subprocess,sys; subprocess.run([sys.executable,'-c'," + repr(grandchild) + "],check=True)"
        completed = subprocess.run(self.command(code, "off"), capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = self.read("off")
        self.assertGreater(report["user_cpu_seconds"] + report["system_cpu_seconds"], 0.14)
        self.assertGreater(report["max_rss_kib"], 60 * 1024)
        self.assertEqual(report["declared_network_mode"], "container_native")
        self.assertEqual(report["resource_scope"], measure.RESOURCE_SCOPE)
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            self.read("on")

    def test_child_signal_exit_preserved_including_sigkill(self):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(sig=sig), tempfile.TemporaryDirectory() as temp:
                self.trial = Path(temp)
                self.output = self.trial / "agent/iorec-measurements"
                result = subprocess.run(self.command(f"import os; os.kill(os.getpid(), {int(sig)})"),
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, -sig, result.stderr)
                self.assertEqual(self.read()["terminating_signal"], sig)

    def test_parent_signal_forwarded_to_child_group_with_result(self):
        code = "import signal; print('ready',flush=True); signal.pause()"
        process = subprocess.Popen(self.command(code), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            self.assertEqual(process.stdout.readline(), b"ready\n")
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGTERM, stderr)
            report = self.read()
            self.assertEqual(report["observer_signals"], [signal.SIGTERM])
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    def test_missing_executable_is_terminal_but_not_valid_measurement(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--output", str(self.output),
                                 "--mode", "off", "--", "/nonexistent/fake-secret"],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 127)
        self.assertNotIn(b"fake-secret", result.stderr)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.read("off")

    def test_incomplete_duplicate_and_tampered_reports_rejected(self):
        subprocess.run(self.command("pass"), check=True, timeout=10)
        directory = next(self.output.iterdir())
        path = directory / "result.json"
        original = path.read_text()
        for field, bad in (("user_cpu_seconds", float("nan")), ("max_rss_kib", True),
                           ("exit_code", False), ("observer_signals", [999]),
                           ("resource_scope", "everything"), ("extra_secret", "never-copy")):
            value = json.loads(original)
            value[field] = bad
            path.write_text(json.dumps(value))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read()
        path.write_text(original)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.read()
        path.write_text(original)
        (self.output / ("0" * 32)).mkdir()
        with self.assertRaisesRegex(ValueError, "exactly_one"):
            self.read()

    def test_bounded_measurement_set_retains_every_valid_invocation(self):
        subprocess.run(self.command("pass"), check=True, timeout=10)
        subprocess.run(self.command("pass"), check=True, timeout=10)
        reports = measure.read_trial_measurements(self.trial, "on")
        self.assertEqual(len(reports), 2)
        self.assertEqual(len({report["invocation_id"] for report in reports}), 2)
        with self.assertRaisesRegex(ValueError, "exactly_one"):
            self.read()

    def test_symlink_fifo_oversize_and_non_private_output_rejected(self):
        subprocess.run(self.command("pass"), check=True, timeout=10)
        path = next(self.output.iterdir()) / "result.json"
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "not_regular"):
            self.read()
        path.unlink()
        path.symlink_to(self.root / "secret")
        with self.assertRaises(OSError):
            self.read()
        path.unlink()
        path.write_bytes(b"x" * 8193)
        with self.assertRaisesRegex(ValueError, "too_large"):
            self.read()
        self.output.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "not_private"):
            measure.measure(self.output, "on", [sys.executable, "-c", "pass"])

    def test_publication_never_overwrites_and_storage_error_keeps_child_exit(self):
        measure.publish(self.root, "once.json", {"value": 1})
        with self.assertRaises(FileExistsError):
            measure.publish(self.root, "once.json", {"value": 2})
        self.assertEqual(json.loads((self.root / "once.json").read_text()), {"value": 1})
        publish = measure.publish
        def fail_final(directory, name, value):
            if name == "result.json":
                raise OSError("test full disk")
            return publish(directory, name, value)
        with mock.patch.object(measure, "publish", side_effect=fail_final), mock.patch.object(sys, "stderr"):
            code = measure.measure(self.output, "on", [sys.executable, "-c", "raise SystemExit(23)"])
        self.assertEqual(code, 23)
        with self.assertRaises(FileNotFoundError):
            self.read()


class BaselineWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "key"
        self.key.write_bytes(bytes(range(32)))
        self.key.chmod(0o600)
        self.binary = self.root / "iorec"
        self.binary.write_bytes(b"fixture")
        self.args = workflow.parser().parse_args(["--task", str(self.root / "task"),
            "--work-dir", str(self.root / "work"), "--key-file", str(self.key),
            "--iorec", str(self.binary), "--recording-mode", "off"])

    def setup_finished_trial(self, w):
        job = w.work.path / "jobs/audit"
        self.trial = job / "task__trial"
        self.trial.mkdir(parents=True)
        workflow.atomic_json(job / "result.json", {"finished_at": "fixture"})
        workflow.atomic_json(self.trial / "result.json", {"finished_at": "2026-09-18T00:00:00Z", "task_name": "task",
            "agent_info": {"name": "codex", "version": "test", "model_info": {"provider": "test", "name": "model"}},
            "agent_result": {"cost_usd": None}, "verifier_result": {"rewards": {"reward": 0}}})
        measure.measure(self.trial / "agent/iorec-measurements", self.args.recording_mode, [sys.executable, "-c", "pass"])
        w.state["launch_intent"] = {"pid": 999999}

    def test_baseline_resume_no_launch_import_or_false_qualification(self):
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            self.setup_finished_trial(w)
            with mock.patch.object(w, "preflight", return_value={}), mock.patch.object(w, "assert_fresh_inputs"), \
                    mock.patch.object(workflow.subprocess, "Popen") as launch, \
                    mock.patch.object(w, "integrity") as integrity, mock.patch.object(w, "import_run") as imported:
                w.run()
                first = w.state["source_identity"]
                w.run()
                self.assertEqual(w.state["source_identity"], first)
                launch.assert_not_called()
                integrity.assert_not_called()
                imported.assert_not_called()
            report = json.loads((work.path / "report.json").read_text())
            self.assertTrue(report["baseline_completed"])
            self.assertFalse(report["qualification_passed"])
            self.assertEqual(report["source"]["benchmark"]["reward"], 0)
            self.assertIsNone(report["trial_summary"]["reported_cost_usd"])
            self.assertNotIn("run_id", report["source"])
            self.assertEqual(set(report["stages"]), {"preflight", "record"})

    def test_missing_measurement_preserves_cost_and_benchmark_but_fails(self):
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            self.setup_finished_trial(w)
            next((self.trial / "agent/iorec-measurements").glob("*/result.json")).unlink()
            with mock.patch.object(w, "assert_fresh_inputs"):
                with self.assertRaisesRegex(workflow.Failure, "measurement_missing_or_invalid"):
                    w.record()
            self.assertEqual(w.state["trial_summary"]["benchmark"]["reward"], 0)
            self.assertIsNone(w.state["trial_summary"]["reported_cost_usd"])

    def test_on_mode_requires_measurement_and_preserves_capture_identity(self):
        self.args.recording_mode = "on"
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            self.setup_finished_trial(w)
            measurement = measure.read_trial_measurement(self.trial, "on")
            run = self.trial / "agent/iorec-runs/run-fixture"
            run.mkdir(parents=True)
            workflow.atomic_json(run / "manifest.json", {"run_id": "run-fixture", "status": "finished",
                "started_at": measurement["started_at"], "exit_code": measurement["exit_code"],
                "storage": {"encryption": {"algorithm": "fixture-only"}}})
            (run / "events.jsonl").write_bytes(b"fixture-only")
            with mock.patch.object(w, "assert_fresh_inputs"):
                result = w.record()
                self.assertEqual(result["run_id"], "run-fixture")
                self.assertEqual(result["measurement"]["recording_mode"], "on")
                self.assertEqual(result["events_sha256"], workflow.digest(run / "events.jsonl"))
                next((self.trial / "agent/iorec-measurements").glob("*/result.json")).unlink()
                with self.assertRaisesRegex(workflow.Failure, "measurement_missing_or_invalid"):
                    w.record()

    def test_on_mode_retains_auxiliary_capture_and_selects_only_clear_dominant(self):
        self.args.recording_mode = "on"
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            self.setup_finished_trial(w)
            measure.measure(self.trial / "agent/iorec-measurements", "on", [sys.executable, "-c", "pass"])
            reports = measure.read_trial_measurements(self.trial, "on")
            reports.sort(key=lambda value: value["invocation_id"])
            for report, wall in zip(reports, (40.0, 1.0), strict=True):
                result_path = self.trial / "agent/iorec-measurements" / report["invocation_id"] / "result.json"
                result = json.loads(result_path.read_text())
                result["wall_seconds"] = wall
                result_path.write_text(json.dumps(result))
            reports = measure.read_trial_measurements(self.trial, "on")
            captures = self.trial / "agent/iorec-runs"
            for index, report in enumerate(reports):
                run = captures / f"run-fixture-{index}"
                run.mkdir(parents=True)
                workflow.atomic_json(run / "manifest.json", {
                    "run_id": run.name, "status": "finished", "started_at": report["started_at"],
                    "exit_code": report["exit_code"], "storage": {"encryption": {"algorithm": "fixture-only"}},
                })
                (run / "events.jsonl").write_bytes(f"fixture-{index}".encode())
            with mock.patch.object(w, "assert_fresh_inputs"):
                result = w.record()
            self.assertEqual(result["measurement"]["wall_seconds"], 40.0)
            selection = result["capture_selection"]
            self.assertEqual(selection["capture_count"], 2)
            self.assertEqual(len(selection["auxiliary_captures"]), 1)
            self.assertNotEqual(selection["auxiliary_captures"][0]["run_id"], result["run_id"])

    def test_baseline_with_any_capture_artifact_is_rejected(self):
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            self.setup_finished_trial(w)
            captures = self.trial / "agent/iorec-runs"
            captures.mkdir()
            (captures / "unfinished").mkdir()
            with mock.patch.object(w, "assert_fresh_inputs"):
                with self.assertRaisesRegex(workflow.Failure, "unexpected_recording"):
                    w.record()

    def test_existing_trial_cannot_be_reinterpreted_as_baseline(self):
        self.args.task, self.args.from_trial = None, self.root / "trial"
        with workflow.Workspace(self.args.work_dir) as work:
            with self.assertRaisesRegex(workflow.Failure, "baseline_requires_fresh"):
                workflow.Workflow(self.args, work).preflight()


if __name__ == "__main__":
    unittest.main()
