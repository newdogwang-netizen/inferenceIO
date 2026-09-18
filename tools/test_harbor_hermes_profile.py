from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from harbor_input_provenance import audit_definitions

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def load(name):
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Parent:
    def __init__(self, *args, **kwargs):
        self.model_name = kwargs.get("model_name")
        self._version = kwargs.get("version")
        self.commands = []

    async def run(self, instruction, environment, context):
        return "parent_run"

    async def exec_as_agent(self, environment, **kwargs):
        self.commands.append(kwargs)
        return types.SimpleNamespace(stdout="Hermes Agent v0.19.0 (fixture)\n")

    async def exec_as_root(self, environment, **kwargs):
        self.commands.append(kwargs)

    @staticmethod
    def _build_config_yaml(model):
        return json.dumps({"model": model, "agent": {"max_turns": 90}, "terminal": {"backend": "local"}})


class HermesProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # These tests run without installing Harbor/PyYAML. The real Harbor
        # installation check is a separate no-provider container qualification.
        modules = {
            "harbor_audit_inputs": audit_definitions(),
            "harbor.agents.installed.hermes": types.SimpleNamespace(Hermes=Parent),
            "yaml": types.SimpleNamespace(safe_load=json.loads, safe_dump=lambda x, **_: json.dumps(x)),
            "hermes_runtime_bundle": load("hermes_runtime_bundle"),
        }
        with mock.patch.dict(sys.modules, modules):
            modules["harbor_iorec_audit_base"] = load("harbor_iorec_audit_base")
            with mock.patch.dict(sys.modules, modules):
                cls.profile = load("harbor_iorec_hermes_audit").IorecHermesAudit

    def test_no_implicit_provider_fallback(self):
        for model, environment in (("anthropic/fixture", {"OPENAI_API_KEY": "fixture"}),
                ("openai/fixture", {"OPENROUTER_API_KEY": "fixture"}), (None, {})):
            with self.subTest(model=model), mock.patch.dict(os.environ, environment, clear=True):
                p = self.profile(model_name=model)
                with self.assertRaisesRegex(ValueError, "no_fallback"):
                    asyncio.run(p.run("test", None, None))
                self.assertEqual(p.commands, [])
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "fixture"}, clear=True):
            p = self.profile(model_name="openai/fixture")
            self.assertEqual(asyncio.run(p.run("test", None, None)), "parent_run")

    def test_exact_version_parse_and_explicit_turn_budget(self):
        p = self.profile()
        self.assertEqual(p.parse_version("Hermes Agent v0.19.0 (2026.7.20)\nPython: 3.11.15\n"), "0.19.0")
        for output in ("unknown", "Hermes Agent v1\nHermes Agent v2\n"):
            with self.assertRaisesRegex(ValueError, "unrecognized_hermes"):
                p.parse_version(output)
        config = json.loads(p._build_config_yaml("openai/fixture"))
        self.assertEqual(config["agent"]["max_turns"], 60)
        self.assertEqual(config["terminal"], {"backend": "local"})

    def test_runtime_digest_checked_before_extraction_and_version_bound(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            p = self.profile()
        p.audit_runtime = {"archive_sha256": "a" * 64,
                           "distributions": [{"name": "hermes-agent", "version": "0.19.0"}]}
        asyncio.run(p.prepare_agent_runtime(None))
        command = p.commands[0]["command"]
        self.assertLess(command.index("sha256sum --check --status"), command.index("tar --extract"))
        self.assertIn("test ! -e /opt/iorec-hermes", command)
        self.assertIn("--keep-old-files", command)
        self.assertIn("env -u TAR_OPTIONS", command)
        self.assertEqual(p._version, "0.19.0")
        self.assertEqual(p.commands[1]["env"]["HERMES_HOME"], "/tmp/hermes")
        self.assertIn("--reuid=10001", p.commands[1]["command"])
        p.audit_runtime["distributions"][0]["version"] = "0.16.0"
        with self.assertRaisesRegex(ValueError, "installed_version_differs"):
            asyncio.run(p.prepare_agent_runtime(None))

    def test_per_call_env_cannot_change_bound_endpoint_or_home(self):
        with mock.patch.dict(os.environ, {"IOREC_HARBOR_UPSTREAM": "https://gateway.example.com/v1"}, clear=True):
            p = self.profile()
        asyncio.run(p.exec_as_agent(None, "hermes version", env={
            "OPENAI_BASE_URL": "https://wrong.example.com", "HERMES_HOME": "/root/.hermes"}))
        actual = p.commands[-1]["env"]
        self.assertEqual(actual["OPENAI_BASE_URL"], "https://gateway.example.com/v1")
        self.assertEqual(actual["HERMES_HOME"], "/tmp/hermes")


if __name__ == "__main__":
    unittest.main()
