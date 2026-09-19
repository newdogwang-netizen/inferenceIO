"""Pinned installed Hermes/Python runtime in the controlled Harbor audit.

The archive includes the actual installed wheel and dependencies, not a floating
installer or an adjacent (possibly older) source checkout. Personal state is not
copied. Only explicit OpenAI-protocol routing is qualified by this profile.
"""
import hashlib
import json
import math
import os
import re
import shlex

import yaml
from harbor.agents.installed.hermes import Hermes
from harbor_audit_inputs import native_uploads
from harbor_iorec_audit_base import EXAMPLES, IorecAuditMixin, host_path
from hermes_runtime_bundle import verify


class IorecHermesAudit(IorecAuditMixin, Hermes):
    AUDIT_AGENT = "hermes"

    def audit_uploads(self):
        bundle = host_path("IOREC_HARBOR_HERMES_BUNDLE", "/missing/hermes-runtime.tar.gz")
        self.audit_runtime = verify(bundle)
        return native_uploads(
            agent="hermes", executable=EXAMPLES / "harbor-audit-hermes", hermes_bundle=bundle,
            iorec=host_path("IOREC_HARBOR_BIN", EXAMPLES.parent / "target/release/iorec"),
            key=host_path("IOREC_HARBOR_KEY_FILE", "/tmp/iorec-tbench/master.key"),
            unshare=host_path("IOREC_HARBOR_UNSHARE_BIN", "/usr/bin/unshare"),
            nsenter=host_path("IOREC_HARBOR_NSENTER_BIN", "/usr/bin/nsenter"))

    async def prepare_agent_runtime(self, environment):
        digest = self.audit_runtime["archive_sha256"]
        # The host validator checks every member and forbids links/extensions
        # that could escape this fresh root-owned destination. Verify those
        # exact bytes again in the container BEFORE privileged extraction.
        await self.exec_as_root(environment, command=(
            "set -eu; chmod 600 /tmp/iorec-hermes-runtime.tar.gz; "
            "printf '%s  %s\\n' " + shlex.quote(digest) + " /tmp/iorec-hermes-runtime.tar.gz "
            "| sha256sum --check --status; "
            "test ! -e /opt/iorec-hermes; umask 022; mkdir -m 755 /opt/iorec-hermes; "
            "env -u TAR_OPTIONS tar --extract --gzip --file /tmp/iorec-hermes-runtime.tar.gz "
            "--directory /opt/iorec-hermes --no-same-owner --no-same-permissions --keep-old-files; "
            "test -x /opt/iorec-hermes/python/bin/python3.11; "
            "mkdir -p /tmp/hermes/sessions /tmp/hermes/skills /tmp/hermes/memories; "
            "chown -R 10001:10001 /tmp/hermes; /tmp/iorec-bin --version"
        ), timeout_sec=180)
        result = await self.exec_as_agent(environment, command="/usr/local/bin/hermes version", timeout_sec=30)
        expected = next(x["version"] for x in self.audit_runtime["distributions"]
                        if x["name"].lower().replace("_", "-") == "hermes-agent")
        if self.parse_version(result.stdout) != expected:
            raise ValueError("hermes_installed_version_differs_from_bundle")
        if self._version is not None and self._version != expected:
            raise ValueError("hermes_requested_version_differs_from_bundle")
        self._version = expected

    def parse_version(self, stdout):
        versions = re.findall(r"^Hermes Agent v([0-9A-Za-z.+_-]+)(?:\s|$)", stdout, re.M)
        if len(versions) != 1:
            raise ValueError("unrecognized_hermes_version_output")
        return versions[0]

    @staticmethod
    def _build_config_yaml(model):
        config = yaml.safe_load(Hermes._build_config_yaml(model))
        config["agent"]["max_turns"] = 60
        return yaml.safe_dump(config, sort_keys=False)

    async def run(self, instruction, environment, context):
        # Harbor otherwise silently falls back to OpenRouter when the native
        # key is absent, contradicting the recorded endpoint/provider inputs.
        if not self.model_name or not self.model_name.startswith("openai/") or not os.environ.get("OPENAI_API_KEY"):
            raise ValueError("hermes_audit_requires_explicit_openai_model_and_key_no_fallback")
        return await super().run(instruction, environment, context)

    def populate_context_post_run(self, context):
        super().populate_context_post_run(context)
        # Harbor currently converts messages but drops Hermes' session-level
        # cost. Preserve a narrowly scoped native estimate, never turn an
        # unknown/default-zero amount into a bill. Multi-session, compression,
        # route changes and missing provenance require separate reconciliation.
        path = self.logs_dir / "hermes-session.jsonl"
        try:
            with path.open("rb") as source:
                raw = source.read((8 << 20) + 1)
            if len(raw) > 8 << 20:
                return
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
            if len(rows) != 1 or not isinstance(rows[0], dict):
                return
            row = rows[0]
            amount = row.get("estimated_cost_usd")
            if (row.get("source") != "cli" or row.get("parent_session_id")
                    or row.get("end_reason") == "compression" or row.get("segments")
                    or row.get("model") not in (self.model_name, self.model_name.split("/", 1)[-1])
                    or row.get("billing_base_url", "").rstrip("/") != self.audit_upstream
                    or row.get("cost_status") != "estimated"
                    or row.get("cost_source") != "official_docs_snapshot"
                    or not isinstance(row.get("pricing_version"), str) or not row["pricing_version"]
                    or type(row.get("api_call_count")) is not int or row["api_call_count"] <= 0
                    or type(amount) not in (int, float) or not math.isfinite(amount) or amount <= 0):
                return
            context.cost_usd = amount
            context.metadata = {**(context.metadata or {}), "iorec_native_cost": {
                "source": "hermes_session_estimate", "cost_status": "estimated",
                "pricing_source": row["cost_source"], "pricing_version": row["pricing_version"],
                "session_export_sha256": hashlib.sha256(raw).hexdigest(),
                "billing_verified": False,
                "scope": "native_single_cli_session_report_not_independent_billing_or_complete_auxiliary_spend"}}
        except (OSError, ValueError, TypeError, AttributeError):
            # Missing or unusable native cost remains None and the shared
            # ledger stops subsequent trials. Do not guess pricing here.
            return

    async def exec_as_agent(self, environment, command, env=None, cwd=None, timeout_sec=None):
        return await super().exec_as_agent(environment, command,
            env={**(env or {}), "HERMES_HOME": "/tmp/hermes"}, cwd=cwd, timeout_sec=timeout_sec)
