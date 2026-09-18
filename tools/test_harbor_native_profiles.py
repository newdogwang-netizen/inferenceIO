from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import harbor_audit_workflow as workflow
from harbor_input_provenance import audit_definitions, fresh_identity

definitions = audit_definitions()
spec = importlib.util.spec_from_file_location("iorec_native_profile_fixture", workflow.ROOT / "examples/harbor_iorec_audit_base.py")
base = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {"harbor_audit_inputs": definitions}):
    spec.loader.exec_module(base)


class NativeProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="iorec-wrapper-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_wrapper(self, agent, argv, input_text="prompt\n'\"$()", mode="on"):
        # Real Bash executes the generated wrapper with isolated fake binaries.
        # No namespace/network/provider is used; only fixed path prefixes change.
        agent_dir, runtime = self.root / "agent", self.root / "runtime"
        agent_dir.mkdir(exist_ok=True)
        runtime.mkdir(exist_ok=True)
        for path, route in [(agent_dir / agent, "native"), (runtime / "ld-linux-x86-64.so.2", "recorder"),
                            (self.root / "iorec", "recorder")]:
            path.write_text("#!" + sys.executable + "\nimport json,sys,os\nprint(json.dumps({"
                            + "'route':" + repr(route) + ", 'argv':sys.argv[1:], 'stdin':sys.stdin.read(),"
                            + "'autoupdater':os.getenv('DISABLE_AUTOUPDATER')}))\nsys.exit(17)\n")
            path.chmod(0o700)
        import shutil
        shutil.copyfile(workflow.ROOT / "examples/harbor_audit_measure.py", agent_dir / "measure.py")
        text = definitions.cli_wrapper(agent, definitions.AGENTS[agent]["upstream"], mode)
        text = text.replace("/opt/iorec-agent", str(agent_dir)).replace("/tmp/iorec-runtime", str(runtime))
        text = text.replace("/tmp/iorec-bin", str(self.root / "iorec"))
        text = text.replace("/logs/agent/iorec-measurements", str(self.root / "measurements"))
        wrapper = self.root / "wrapper"
        wrapper.write_text(text)
        result = subprocess.run(["/bin/bash", str(wrapper), *argv], input=input_text, text=True,
                                capture_output=True, timeout=10, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 17, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["stdin"], input_text)
        return output

    def test_exact_arguments_stdin_and_exit_code_preserved_for_both_agents(self):
        for agent in definitions.AGENTS:
            with self.subTest(agent=agent):
                argv = ["exec" if agent == "codex" else "--print", "--", "", "codex exec '$HOME' $(false)\n中文"]
                output = self.run_wrapper(agent, argv)
                self.assertEqual(output["route"], "recorder")
                boundary = output["argv"].index("--")
                self.assertEqual(output["argv"][boundary + 2:], argv)
                self.assertIn("--pcap", output["argv"])
                self.assertIn("--task-netns", output["argv"])
                self.assertIn("--transparent-proxy", output["argv"])
                self.assertEqual(output["argv"][output["argv"].index("--adapter") + 1], agent)

    def test_only_exact_single_information_argument_bypasses_recording(self):
        for agent in definitions.AGENTS:
            self.assertEqual(self.run_wrapper(agent, ["--version"])["route"], "native")
            self.assertEqual(self.run_wrapper(agent, ["--help", "--print", "hello"])["route"], "recorder")
        self.assertEqual(self.run_wrapper("claude", ["--version"])["autoupdater"], "1")

    def test_claude_self_exec_hooks_require_native_recorder_entry(self):
        claude = definitions.cli_wrapper("claude", definitions.AGENTS["claude"]["upstream"])
        codex = definitions.cli_wrapper("codex", definitions.AGENTS["codex"]["upstream"])
        self.assertIn(" -- /tmp/iorec-bin run", claude)
        self.assertNotIn("ld-linux", claude)
        self.assertIn("ld-linux", codex)

    def test_off_is_exact_native_invocation_with_same_observer(self):
        argv = ["chat", "--", "", "prompt $(false)\n中文"]
        for agent in definitions.AGENTS:
            output = self.run_wrapper(agent, argv, mode="off")
            self.assertEqual(output["route"], "native")
            self.assertEqual(output["argv"], argv)
            wrapper = definitions.cli_wrapper(agent, definitions.AGENTS[agent]["upstream"], "off")
            self.assertIn("/usr/bin/python3 -I -B /opt/iorec-agent/measure.py", wrapper)
            self.assertNotIn("--task-netns", wrapper)
            self.assertNotIn("/tmp/iorec-bin", wrapper)
        with self.assertRaisesRegex(ValueError, "invalid_recording_mode"):
            definitions.cli_wrapper("codex", definitions.AGENTS["codex"]["upstream"], "unknown")

    def test_hermes_version_and_exact_session_export_only_bypass(self):
        export = ["sessions", "export", "/logs/agent/hermes-session.jsonl", "--source", "cli"]
        self.assertEqual(self.run_wrapper("hermes", ["version"])["route"], "native")
        self.assertEqual(self.run_wrapper("hermes", export)["route"], "native")
        self.assertEqual(self.run_wrapper("hermes", export + ["--model", "openai/fixture"])["route"], "recorder")
        self.assertEqual(self.run_wrapper("hermes", ["version", "chat"])["route"], "recorder")
        self.assertEqual(self.run_wrapper("hermes", ["--yolo", "chat", "-q", "test"])["route"], "recorder")

    def test_hermes_configuration_uses_runtime_profile_not_unhandled_turn_flag(self):
        args = workflow.parser().parse_args(["--work-dir", str(self.root), "--task", str(self.root),
            "--key-file", str(self.root / "key"), "--agent", "hermes", "--model", "openai/fixture",
            "--hermes-bundle", str(self.root / "runtime.tar.gz")])
        agent = workflow.harbor_config(args, self.root)["agents"][0]
        self.assertEqual(agent["import_path"], "harbor_iorec_hermes_audit:IorecHermesAudit")
        self.assertEqual(agent["kwargs"], {})

    def test_endpoint_validation_has_no_shell_injection_or_secret_urls(self):
        self.assertEqual(definitions.upstream_url("https://api.example.com:443/anthropic/"),
                         "https://api.example.com:443/anthropic")
        for value in ("http://api.example.com", "https://127.0.0.1", "https://localhost", "https://[::1]",
                      "https://user:secret@api.example.com", "https://api.example.com?key=secret",
                      "https://api.example.com/$(touch%20x)", "https://api.example.com/../v1", "https://api.example.com\n"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "non_loopback_https"):
                definitions.cli_wrapper("claude", value)

    def test_claude_configuration_has_own_profile_flags_and_budget(self):
        args = workflow.parser().parse_args(["--work-dir", str(self.root), "--task", str(self.root),
            "--key-file", str(self.root / "key"), "--agent", "claude", "--model", "anthropic/fixture",
            "--agent-budget-usd", "0.5"])
        config = workflow.harbor_config(args, self.root)
        agent = config["agents"][0]
        self.assertEqual(agent["import_path"], "harbor_iorec_claude_audit:IorecClaudeAudit")
        self.assertEqual(agent["kwargs"], {"max_turns": 60, "max_budget_usd": "0.5"})
        self.assertEqual(config["retry"]["max_retries"], 0)

    def test_mixin_keeps_prompt_text_unchanged_and_confines_target(self):
        class Parent:
            def __init__(self, *args, **kwargs):
                self.args = kwargs
            async def exec_as_agent(self, environment, **kwargs):
                return kwargs
        class Profile(base.IorecAuditMixin, Parent):
            AUDIT_AGENT = "claude"
        with mock.patch.dict(os.environ, {"IOREC_HARBOR_UPSTREAM": "https://gateway.example.com/anthropic"}, clear=True):
            p = Profile(extra_env={"ANTHROPIC_BASE_URL": "https://wrong.example.com"})
        self.assertEqual(p.args["extra_env"]["ANTHROPIC_BASE_URL"], "https://gateway.example.com/anthropic")
        command = "printf '%s' 'codex exec --marker'"
        actual = asyncio.run(p.exec_as_agent(None, command, env={"HOME": "/root", "USER": "root",
            "ANTHROPIC_BASE_URL": "https://wrong.example.com"}, timeout_sec=42))
        self.assertIn("--reuid=10001 --regid=10001", actual["command"])
        import shlex
        self.assertEqual(shlex.split(actual["command"])[-1], "set -o pipefail; " + command)
        self.assertEqual(actual["env"]["HOME"], "/home/iorecagent")
        self.assertEqual(actual["env"]["ANTHROPIC_BASE_URL"], "https://gateway.example.com/anthropic")
        self.assertEqual(actual["timeout_sec"], 42)
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_USE_BEDROCK": "1"}, clear=True):
            with self.assertRaisesRegex(ValueError, "direct_anthropic"):
                Profile()


if __name__ == "__main__":
    unittest.main()
