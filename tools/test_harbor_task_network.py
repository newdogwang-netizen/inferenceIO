import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import harbor_task_network as network
import harbor_input_provenance as inputs
import harbor_audit_workflow as workflow


class TaskNetworkTests(unittest.TestCase):
    subnet = "10.203.240.0/24"
    network_id = "a" * 64

    def setUp(self):
        clean_env = mock.patch.dict(network.os.environ, {}, clear=True)
        clean_env.start()
        self.addCleanup(clean_env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.task = self.root / "task"
        (self.task / "environment").mkdir(parents=True)
        (self.task / "task.toml").write_text('[agent]\ntimeout_sec=1800\n')

    def reply(self, value=b"", code=0, stderr=b""):
        return SimpleNamespace(returncode=code, stdout=value, stderr=stderr)

    def test_restricted_canonical_private_subnet_and_overlay(self):
        for subnet in ("10.203.240.0/24", "172.16.240.0/28", "192.168.250.0/24"):
            self.assertEqual(str(network.validated_subnet(subnet)), subnet)
        for subnet in (None, "0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/29", "10.0.0.1/24",
                       "127.0.0.0/24", "169.254.0.0/24", "198.18.0.0/24", "8.8.8.0/24",
                       "10.203.240.0/255.255.255.0", "fd00::/64", "10.0.0.0/24\n", "--internal"):
            with self.subTest(subnet=subnet), self.assertRaises(network.NetworkFailure):
                network.validated_subnet(subnet)
        self.assertEqual(network.network_compose(self.subnet), {
            "networks": {"default": {"ipam": {"config": [{"subnet": self.subnet}]}}}})

    def test_task_instructions_unchanged_and_unsupported_topologies_rejected(self):
        path = self.task / "task.toml"
        before = path.read_bytes()
        self.assertEqual(network.task_network_input(self.task, self.subnet)["subnet"], self.subnet)
        self.assertEqual(path.read_bytes(), before)
        path.write_text('[verifier]\nenvironment_mode="separate"\n')
        with self.assertRaisesRegex(network.NetworkFailure, "shared_verifier"):
            network.task_network_input(self.task, self.subnet)
        path.write_bytes(before)
        path.write_text('[environment]\nallow_internet=false\n')
        with self.assertRaisesRegex(network.NetworkFailure, "egress_sidecar"):
            network.task_network_input(self.task, self.subnet)
        path.write_bytes(before)
        (self.task / "environment/docker-compose.yaml").write_text("services: {}")
        with self.assertRaisesRegex(network.NetworkFailure, "single_service"):
            network.task_network_input(self.task, self.subnet)

    def inspect(self, subnet="172.18.0.0/16", route="10.148.0.0/24"):
        return [self.reply(b'"unix:///var/run/docker.sock"'), self.reply((self.network_id+"\n").encode()),
                self.reply(json.dumps([{"Subnet": subnet}]).encode()+b"\n"),
                self.reply(json.dumps([{"dst":"default"},{"dst":route}]).encode())]

    @mock.patch.object(network, "command")
    def test_read_only_overlap_check_includes_other_routing_tables(self, command):
        command.side_effect = self.inspect()
        result = network.assert_no_overlap(self.subnet)
        self.assertEqual(result["docker_networks_checked"], 1)
        self.assertEqual(command.call_args.args[0], ["ip", "-j", "-4", "route", "show", "table", "all"])
        for route, subnet in (("10.203.0.0/16", "172.18.0.0/16"), ("10.148.0.0/24", "10.203.240.0/25")):
            command.side_effect = self.inspect(subnet, route)
            with self.assertRaisesRegex(network.NetworkFailure, "overlaps"):
                network.assert_no_overlap(self.subnet)
        for call in command.call_args_list:
            self.assertNotIn("create", call.args[0])
            self.assertNotIn("rm", call.args[0])

    @mock.patch.object(network, "command")
    def test_inventory_errors_fail_closed_without_allocating(self, command):
        variants = [
            [self.reply(b'"unix:///var/run/docker.sock"'), self.reply(b"not-an-id\n")],
            [self.reply(b"", code=1)],
            self.inspect()[:2] + [self.reply(b"bad-json")],
            self.inspect()[:3] + [self.reply(b'{"not":"routes"}')],
            self.inspect()[:3] + [self.reply(b'[{}]')],
        ]
        for replies in variants:
            command.reset_mock()
            command.side_effect = replies
            with self.assertRaises(network.NetworkFailure):
                network.assert_no_overlap(self.subnet)
            self.assertTrue(all("create" not in c.args[0] for c in command.call_args_list))

    @mock.patch.object(network, "command")
    def test_remote_daemon_cannot_use_local_host_route_inventory(self, command):
        for endpoint in ("ssh://worker", "tcp://127.0.0.1:2375", "tcp://remote:2376"):
            command.reset_mock()
            with mock.patch.dict(network.os.environ, {"DOCKER_HOST":endpoint}):
                with self.assertRaisesRegex(network.NetworkFailure, "local_unix"):
                    network.assert_no_overlap(self.subnet)
            command.assert_not_called()
        command.return_value = self.reply(b'"ssh://worker"')
        with self.assertRaisesRegex(network.NetworkFailure, "local_unix"):
            network.assert_no_overlap(self.subnet)

    @mock.patch.object(network, "assert_no_overlap", return_value={"subnet": "10.203.240.0/24"})
    @mock.patch.object(network.secrets, "token_hex", return_value="b" * 32)
    @mock.patch.object(network, "command")
    def test_probe_only_removes_its_own_labelled_empty_immutable_id(self, command, _, inspect):
        command.side_effect = [self.reply((self.network_id+"\n").encode()),
            self.reply(json.dumps({"id":self.network_id,"labels":{network.LABEL:"b"*32},"endpoints":0}).encode()),
            self.reply()]
        report = network.probe_network(self.subnet)
        self.assertEqual(report["allocation_probe"], "created_and_removed")
        self.assertIs(report["reserves_subnet"], False)
        self.assertEqual(command.call_args.args[0], ["docker", "network", "rm", self.network_id])
        self.assertEqual(command.call_args_list[0].args[0][-1], "iorec-network-probe-"+"b"*32)
        self.assertEqual(command.call_args_list[1].args[0][-1], "iorec-network-probe-"+"b"*32)

    @mock.patch.object(network, "command")
    def test_cleanup_never_removes_foreign_or_connected_network(self, command):
        for labels, endpoints, identity in (({},0,self.network_id),({network.LABEL:"different"},0,self.network_id),
                ({network.LABEL:"owned"},1,self.network_id),({network.LABEL:"owned"},0,"--all")):
            command.reset_mock()
            command.return_value = self.reply(json.dumps({"id":identity,"labels":labels,"endpoints":endpoints}).encode())
            with self.assertRaisesRegex(network.NetworkFailure, "no_removal"):
                network.cleanup_probe("exact-name", "owned")
            self.assertEqual(command.call_count, 1)

    @mock.patch.object(network, "assert_no_overlap", return_value={})
    @mock.patch.object(network.secrets, "token_hex", return_value="b" * 32)
    @mock.patch.object(network, "command")
    def test_allocation_failure_does_not_become_success(self, command, _, inspect):
        command.side_effect = [self.reply(code=1,stderr=b"predefined address pools fully subnetted"),
                               self.reply(code=1,stderr=b"network iorec-network-probe-"+b"b"*32+b" not found")]
        with self.assertRaisesRegex(network.NetworkFailure, "allocation_probe_failed"):
            network.probe_network(self.subnet)
        self.assertTrue(all("rm" not in c.args[0] for c in command.call_args_list))

    @mock.patch.object(network, "command")
    def test_cleanup_uncertainty_and_failure_are_not_success(self, command):
        for error in (b"daemon unavailable", b"context not found", b"network different-name not found"):
            command.return_value = self.reply(code=1, stderr=error)
            with self.assertRaisesRegex(network.NetworkFailure, "cleanup_unverified"):
                network.cleanup_probe("exact-name", "owned")
        command.side_effect = [self.reply(json.dumps({"id":self.network_id,"labels":{network.LABEL:"owned"},"endpoints":0}).encode()), self.reply(code=1)]
        with self.assertRaisesRegex(network.NetworkFailure, "cleanup_failed"):
            network.cleanup_probe("exact-name", "owned")

    def test_overlay_bound_to_inputs_and_drift_fences_launch(self):
        key = self.root / "key"
        key.write_bytes(b"a" * 32)
        key.chmod(0o600)
        args = workflow.parser().parse_args(["--work-dir", str(self.root / "work"), "--task", str(self.task),
            "--model", "openai/fixture", "--key-file", str(key), "--task-network-subnet", self.subnet])
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            overlay = work.path / "task-network.compose.json"
            workflow.atomic_json(overlay, network.network_compose(self.subnet))
            expected = {"harbor": {"launcher": {"path": "/fixture/harbor"}}}
            w.state["config"] = {"fresh_inputs": expected, "key_fingerprint": workflow.digest(key),
                                 "task_network_compose": inputs.file_identity(overlay)}
            self.assertEqual(workflow.harbor_config(args, work.path)["environment"]["extra_docker_compose"][-1], str(overlay))
            with mock.patch.object(workflow, "fresh_identity", return_value=expected):
                w.assert_fresh_inputs()
                workflow.atomic_json(overlay, network.network_compose("10.203.241.0/24"))
                with mock.patch.object(workflow.subprocess, "Popen") as launch:
                    with self.assertRaisesRegex(workflow.Failure, "network_overlay_changed"):
                        w.record()
                    launch.assert_not_called()
                    self.assertNotIn("launch_intent", w.state)

    def test_old_m3_declaration_cannot_silently_acquire_new_network_option(self):
        args = workflow.parser().parse_args(["--work-dir", str(self.root / "work"), "--task", str(self.task),
            "--key-file", str(self.root / "key"), "--experiment-plan", str(self.root / "old-plan.json"),
            "--task-network-subnet", self.subnet])
        with workflow.Workspace(args.work_dir) as work:
            with self.assertRaisesRegex(workflow.Failure, "not_declared_by_M3"):
                workflow.Workflow(args, work).preflight()

    def preflight_fixture(self):
        key, binary, version = self.root / "key", self.root / "iorec", self.root / "version"
        key.write_bytes(b"a" * 32)
        key.chmod(0o600)
        binary.write_bytes(b"non-executable fixture")
        version.write_text("Harbor 0.22.0\n")
        args = workflow.parser().parse_args(["--work-dir", str(self.root / "work"), "--task", str(self.task),
            "--key-file", str(key), "--iorec", str(binary), "--model", "openai/fixture",
            "--task-network-subnet", self.subnet, "--preflight-only"])
        return args, version

    def fake_command(self, work, version):
        def run(*args, **kwargs):
            (work.path / "scratch").mkdir(mode=0o700, exist_ok=True)
            return version
        return run

    def test_allocation_failure_is_preflight_failure_before_any_launch_intent(self):
        args, version = self.preflight_fixture()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(workflow, "fresh_identity", return_value={"harbor":{"launcher":{"path":"/fixture/harbor"}}}), \
                    mock.patch.object(w, "command", side_effect=self.fake_command(work, version)), \
                    mock.patch.object(workflow, "api_request", return_value={"ok":True}), \
                    mock.patch.object(workflow, "probe_network", side_effect=network.NetworkFailure("task_network_allocation_probe_failed_no_model_launch")), \
                    mock.patch.object(workflow.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(network.NetworkFailure, "allocation_probe_failed"):
                    w.run()
                launch.assert_not_called()
            self.assertNotIn("launch_intent", w.state)
            report = workflow.read_json(work.path / "report.json")
            self.assertFalse(report["qualification_passed"])
            self.assertEqual(report["stages"]["preflight"]["error"], "task_network_allocation_probe_failed_no_model_launch")

    def test_existing_trial_evidence_resume_does_not_allocate_another_network(self):
        args, version = self.preflight_fixture()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(workflow, "fresh_identity", return_value={"harbor":{"launcher":{"path":"/fixture/harbor"}}}), \
                    mock.patch.object(w, "command", side_effect=self.fake_command(work, version)), \
                    mock.patch.object(workflow, "api_request", return_value={"ok":True}), \
                    mock.patch.object(workflow, "probe_network", return_value={"allocation_probe":"created_and_removed"}) as probe:
                w.preflight()
                probe.assert_called_once_with(self.subnet)
                w.state["launch_intent"] = {"exit_code":0}
                probe.reset_mock()
                w.preflight()
                probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
