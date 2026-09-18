from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import harbor_input_provenance as inputs
import harbor_audit_workflow as workflow


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.task = self.base / "task"
        self.task.mkdir()
        (self.task / "task.toml").write_text('version = "1.0"\n')
        self.args = SimpleNamespace(task=self.task, codex=self.base / "codex",
                                    iorec=self.base / "iorec", key_file=self.base / "key")
        for name in ("codex", "codex-code-mode-host", "iorec", "key"):
            (self.base / name).write_bytes((name + "-fixture").encode())
        self.args.key_file.chmod(0o600)
        self.runtime = {"launcher": {"path": str(self.base / "harbor")},
                        "package": {"sha256": "fixture"}, "package_version": "0.22.0"}

    def test_file_identity_detects_same_length_change_and_permissions(self):
        path = self.base / "codex"
        before = inputs.file_identity(path)
        self.assertEqual(before["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        path.write_bytes(b"X" * path.stat().st_size)
        self.assertNotEqual(inputs.file_identity(path), before)
        before = inputs.file_identity(path)
        path.chmod(0o500)
        self.assertNotEqual(inputs.file_identity(path), before)

    def test_file_retarget_and_fifo_fail_closed_without_blocking(self):
        link = self.base / "link"
        link.symlink_to(self.base / "codex")
        before = inputs.file_identity(link)
        link.unlink()
        link.symlink_to(self.base / "iorec")
        self.assertNotEqual(inputs.file_identity(link), before)
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(inputs.InputFailure, "not_regular"):
            inputs.file_identity(fifo)

    def test_file_change_while_hashing_is_rejected(self):
        real = os.fstat
        calls = 0
        def changing(fd):
            nonlocal calls
            calls += 1
            value = real(fd)
            if calls == 2:
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
                changed = {k: getattr(value, k) for k in fields}
                changed["st_mtime_ns"] += 1
                return SimpleNamespace(**changed)
            return value
        with mock.patch.object(os, "fstat", side_effect=changing):
            with self.assertRaisesRegex(inputs.InputFailure, "changed_while_hashing"):
                inputs.file_identity(self.base / "codex")

    def test_tree_order_metadata_ignore_and_drift(self):
        (self.task / "z").write_text("last")
        (self.task / "a").write_text("first")
        before = inputs.tree_identity(self.task, ignored_names=(".git",))
        (self.task / ".git").mkdir()
        (self.task / ".git/config").write_text("ignored repository metadata")
        self.assertEqual(inputs.tree_identity(self.task, ignored_names=(".git",)), before)
        (self.task / "a").write_text("other")
        self.assertNotEqual(inputs.tree_identity(self.task, ignored_names=(".git",)), before)

    def test_tree_rejects_symlink_empty_and_size_limits(self):
        link = self.task / "outside"
        link.symlink_to(self.base / "key")
        with self.assertRaisesRegex(inputs.InputFailure, "symlinks"):
            inputs.tree_identity(self.task)
        link.unlink()
        with mock.patch.object(inputs, "MAX_TREE_BYTES", 1):
            with self.assertRaisesRegex(inputs.InputFailure, "limit"):
                inputs.tree_identity(self.task)
        empty = self.base / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(inputs.InputFailure, "empty"):
            inputs.tree_identity(empty)

    def test_environment_cannot_shadow_python_or_override_profile(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": "/hostile", "PYTHONHOME": "/hostile",
                "PYTHONUSERBASE": "/hostile", "IOREC_HARBOR_CODEX_BIN": "/other",
                "OPENAI_API_KEY": "fixture-only-not-logged"}, clear=True):
            env = inputs.harbor_environment()
        self.assertEqual(env["PYTHONPATH"], str(inputs.ROOT / "examples"))
        self.assertNotIn("PYTHONHOME", env)
        self.assertNotIn("PYTHONUSERBASE", env)
        self.assertNotIn("IOREC_HARBOR_CODEX_BIN", env)
        # Credentials remain available to Harbor, never in the input manifest.
        self.assertEqual(env["OPENAI_API_KEY"], "fixture-only-not-logged")

    def test_runtime_rejects_ambiguous_shebang_without_executing(self):
        launcher = self.base / "harbor"
        launcher.write_text("#!/usr/bin/env python3\n")
        with mock.patch.object(inputs.subprocess, "run") as run:
            with self.assertRaisesRegex(inputs.InputFailure, "explicit_python"):
                inputs.harbor_runtime(launcher)
            run.assert_not_called()

    @mock.patch.object(inputs, "harbor_runtime")
    def test_actual_upload_set_is_pinned_but_key_is_not_public(self, runtime):
        runtime.return_value = self.runtime
        identity = inputs.fresh_identity(self.args)
        uploads = identity["uploads"]
        self.assertEqual(len(uploads), 14)
        self.assertIn("/opt/iorec-agent/measure.py", uploads)
        for remote in ("/tmp/iorec-runtime/libc.so.6", "/tmp/iorec-runtime/libselinux.so.1",
                       "/usr/bin/unshare", "/tmp/iorec-runtime/unshare",
                       "/opt/iorec-agent/codex-code-mode-host"):
            self.assertIn(remote, uploads)
        self.assertNotIn("/tmp/iorec.key", uploads)
        self.assertNotIn(str(self.args.key_file), json.dumps(identity))
        self.assertNotIn(hashlib.sha256(self.args.key_file.read_bytes()).hexdigest(), json.dumps(identity))
        (self.base / "codex-code-mode-host").write_text("changed helper")
        self.assertNotEqual(inputs.fresh_identity(self.args), identity)

    @mock.patch.object(inputs, "harbor_runtime")
    def test_recording_mode_is_bound_in_manifest_and_wrapper(self, runtime):
        runtime.return_value = self.runtime
        on = inputs.fresh_identity(self.args)
        self.args.recording_mode = "off"
        off = inputs.fresh_identity(self.args)
        self.assertNotEqual(on["cli_wrapper_sha256"], off["cli_wrapper_sha256"])
        self.assertEqual(on["uploads"], off["uploads"])
        self.assertEqual(off["recording_mode"], "off")

    @mock.patch.object(inputs, "harbor_runtime")
    def test_hermes_bundle_launcher_and_verifier_are_actual_bound_inputs(self, runtime):
        import importlib.util
        spec = importlib.util.spec_from_file_location("bundle_identity_fixture", inputs.ROOT / "examples/hermes_runtime_bundle.py")
        bundle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bundle)
        runtime.return_value = self.runtime
        python, site = self.base / "python-source", self.base / "site"
        (python / "bin").mkdir(parents=True)
        (python / "bin/python3.11").write_bytes(b"python fixture")
        (site / "hermes_cli").mkdir(parents=True)
        (site / "hermes_cli/main.py").write_text("fixture = True\n")
        (site / "hermes_agent-0.19.0.dist-info").mkdir()
        (site / "hermes_agent-0.19.0.dist-info/METADATA").write_text("Name: hermes-agent\nVersion: 0.19.0\n")
        self.args.agent, self.args.hermes_bundle = "hermes", self.base / "runtime.tar.gz"
        built = bundle.build(python, site, self.args.hermes_bundle)
        identity = inputs.fresh_identity(self.args)
        self.assertEqual(identity["hermes_runtime"]["archive_sha256"], built["archive_sha256"])
        self.assertIn("/tmp/iorec-hermes-runtime.tar.gz", identity["uploads"])
        self.assertTrue(identity["uploads"]["/opt/iorec-agent/hermes"]["path"].endswith("/examples/harbor-audit-hermes"))
        self.assertIn("examples/hermes_runtime_bundle.py", identity["controller"])
        self.assertNotIn("/tmp/iorec.key", identity["uploads"])
        self.args.hermes_bundle.chmod(0o400)
        self.assertNotEqual(inputs.fresh_identity(self.args), identity)
        self.args.hermes_bundle = None
        with self.assertRaisesRegex(ValueError, "hermes_requires_pinned"):
            inputs.fresh_identity(self.args)

    def test_workflow_rejects_drift_before_new_launch_and_after_finished_trial(self):
        args = workflow.parser().parse_args(["--work-dir", str(self.base / "work"),
            "--task", str(self.task), "--model", "openai/fixture", "--key-file", str(self.args.key_file)])
        expected = {"harbor": self.runtime, "uploads": {"library": "old"}}
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            w.state["config"] = {"fresh_inputs": expected,
                "key_fingerprint": workflow.digest(self.args.key_file)}
            with mock.patch.object(workflow, "fresh_identity", return_value={**expected, "drift": True}):
                with mock.patch.object(workflow.subprocess, "Popen") as launch:
                    with self.assertRaisesRegex(workflow.Failure, "inputs_changed"):
                        w.record()
                    launch.assert_not_called()
                    self.assertNotIn("launch_intent", w.state)
            job = work.path / "jobs/audit"
            (job / "task__done").mkdir(parents=True)
            (job / "result.json").write_text("{}")
            (job / "task__done/result.json").write_text("{}")
            w.state["launch_intent"] = {"pid": 999999}
            with mock.patch.object(workflow, "fresh_identity", return_value={**expected, "drift": True}):
                with mock.patch.object(workflow.subprocess, "Popen") as launch:
                    with self.assertRaisesRegex(workflow.Failure, "inputs_changed"):
                        w.record()
                    launch.assert_not_called()
                    self.assertTrue((job / "task__done/result.json").is_file())

    def test_workflow_rejects_missing_current_preflight_and_key_drift(self):
        args = workflow.parser().parse_args(["--work-dir", str(self.base / "work"),
            "--task", str(self.task), "--key-file", str(self.args.key_file)])
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with self.assertRaisesRegex(workflow.Failure, "requires_current_input"):
                w.assert_fresh_inputs()
            expected = {"harbor": self.runtime}
            w.state["config"] = {"fresh_inputs": expected, "key_fingerprint": "old"}
            with mock.patch.object(workflow, "fresh_identity", return_value=expected):
                with self.assertRaisesRegex(workflow.Failure, "inputs_changed"):
                    w.assert_fresh_inputs()

    def test_preflight_only_never_launches_or_claims_qualification(self):
        args = workflow.parser().parse_args(["--work-dir", str(self.base / "work"),
            "--task", str(self.task), "--key-file", str(self.args.key_file), "--preflight-only"])
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", return_value={"mode": "fresh_trial"}):
                with mock.patch.object(w, "record") as record:
                    w.run()
                    record.assert_not_called()
            report = workflow.read_json(work.path / "report.json")
            self.assertEqual(report["workflow_status"], "preflight_only")
            self.assertFalse(report["qualification_passed"])
            self.assertTrue(report["plaintext_staging_cleaned"])
            self.assertNotIn("launch_intent", w.state)
            self.assertEqual(list(report["stages"]), ["preflight"])


if __name__ == "__main__":
    unittest.main()
