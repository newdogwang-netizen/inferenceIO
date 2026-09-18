import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import harbor_input_provenance as inputs
import harbor_audit_workflow as workflow


class TaskImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.task = Path(self.temp.name) / "task"
        (self.task / "environment").mkdir(parents=True)
        (self.task / "task.toml").write_text('[environment]\ndocker_image="example/task:tag"\n')
        self.ref = "example/task@sha256:" + "a" * 64
        self.image = {"id": "sha256:" + "b" * 64, "digests": [self.ref], "os": "linux", "architecture": "amd64"}

    def test_digest_required_and_compose_forbids_pulls(self):
        self.assertEqual(inputs.image_compose(self.ref), {"services": {"main": {"image": self.ref, "pull_policy": "never"}}})
        for value in (None, "example/task:latest", "sha256:" + "a" * 64,
                      "https://user:secret@registry/task", "x@sha256:" + "a" * 63, "x\n@sha256:" + "a" * 64):
            with self.subTest(value=value), self.assertRaises(inputs.InputFailure):
                inputs.image_compose(value)

    @mock.patch.object(inputs, "docker_image_identity")
    def test_exact_published_image_required(self, inspect):
        inspect.return_value = self.image
        before = (self.task / "task.toml").read_bytes()
        result = inputs.task_image_input(self.task, self.ref)
        self.assertEqual(result["declared_reference"], "example/task:tag")
        self.assertEqual(result["image_id"], self.image["id"])
        self.assertEqual((self.task / "task.toml").read_bytes(), before)
        self.assertEqual(inspect.call_args_list, [mock.call(self.ref), mock.call("example/task:tag")])
        inspect.side_effect = [self.image, {**self.image, "id": "sha256:" + "c" * 64}]
        with self.assertRaisesRegex(inputs.InputFailure, "differs_from_published"):
            inputs.task_image_input(self.task, self.ref)

    @mock.patch.object(inputs, "docker_image_identity")
    def test_missing_digest_rejected_even_if_id_looks_plausible(self, inspect):
        inspect.return_value = {**self.image, "digests": []}
        with self.assertRaisesRegex(inputs.InputFailure, "digest_not_present"):
            inputs.task_image_input(self.task, self.ref)

    @mock.patch.object(inputs, "docker_image_identity")
    def test_separate_verifier_and_multi_service_never_silently_replaced(self, inspect):
        with (self.task / "task.toml").open("a") as f:
            f.write('[verifier]\nenvironment_mode="separate"\n')
        with self.assertRaisesRegex(inputs.InputFailure, "shared_verifier"):
            inputs.task_image_input(self.task, self.ref)
        inspect.assert_not_called()
        (self.task / "task.toml").write_text('[environment]\ndocker_image="example/task:tag"\n')
        (self.task / "environment/compose.yaml").write_text("services: {}")
        with self.assertRaisesRegex(inputs.InputFailure, "single_service"):
            inputs.task_image_input(self.task, self.ref)

    @mock.patch.object(inputs.subprocess, "run")
    def test_docker_probe_has_no_pull_or_sensitive_metadata(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(self.image).encode())
        self.assertEqual(inputs.docker_image_identity(self.ref), self.image)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["docker", "image", "inspect"])
        self.assertIn(self.ref, argv)
        self.assertNotIn("Config.Env", " ".join(argv))
        for changed in ({**self.image, "architecture": "arm64"}, {**self.image, "os": "windows"}):
            run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(changed).encode())
            with self.assertRaisesRegex(inputs.InputFailure, "linux_amd64"):
                inputs.docker_image_identity(self.ref)
        run.return_value = SimpleNamespace(returncode=1, stdout=b"")
        with self.assertRaisesRegex(inputs.InputFailure, "not_available_locally"):
            inputs.docker_image_identity(self.ref)

    def test_generated_overlay_is_last_and_tampering_prevents_launch(self):
        root = Path(self.temp.name)
        key = root / "key"
        key.write_bytes(b"a" * 32)
        key.chmod(0o600)
        args = workflow.parser().parse_args(["--work-dir", str(root / "work"), "--task", str(self.task),
            "--model", "openai/fixture", "--key-file", str(key), "--task-image", self.ref,
            "--verifier-timeout", "900"])
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            overlay = work.path / "task-image.compose.json"
            workflow.atomic_json(overlay, inputs.image_compose(self.ref))
            expected = {"harbor": {"launcher": {"path": "/fixture/harbor"}}}
            w.state["config"] = {"fresh_inputs": expected, "key_fingerprint": workflow.digest(key),
                                 "task_image_compose": inputs.file_identity(overlay)}
            overlays = workflow.harbor_config(args, work.path)["environment"]["extra_docker_compose"]
            self.assertEqual(overlays[-1], str(overlay))
            self.assertEqual(workflow.harbor_config(args, work.path)["verifier"]["override_timeout_sec"], 900)
            with mock.patch.object(workflow, "fresh_identity", return_value=expected):
                w.assert_fresh_inputs()
                workflow.atomic_json(overlay, {"services": {"main": {"image": "other:latest"}}})
                with mock.patch.object(workflow.subprocess, "Popen") as launch:
                    with self.assertRaisesRegex(workflow.Failure, "overlay_changed"):
                        w.record()
                    launch.assert_not_called()
                    self.assertNotIn("launch_intent", w.state)


if __name__ == "__main__":
    unittest.main()
