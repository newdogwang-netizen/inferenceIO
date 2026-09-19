"""Pinned installed Hermes/Python runtime in the controlled Harbor audit.

The archive includes the actual installed wheel and dependencies, not a floating
installer or an adjacent (possibly older) source checkout. Personal state is not
copied. Only explicit OpenAI-protocol routing is qualified by this profile.
"""
import hashlib
import json
import math
import os
from decimal import Decimal
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
        # The recorder overlays existing Hermes home entries by symlink. If
        # state.db first appears inside that temporary overlay, it disappears
        # at recorder exit and Harbor's later export sees an empty session DB.
        # Initialize the native database before recording, without a model call.
        await self.exec_as_agent(environment, command=(
            "/opt/iorec-hermes/python/bin/python3.11 -I -B -c "
            + shlex.quote("from hermes_state import SessionDB; db = SessionDB(); db.close()")
        ), timeout_sec=30)

    def parse_version(self, stdout):
        versions = re.findall(r"^Hermes Agent v([0-9A-Za-z.+_-]+)(?:\s|$)", stdout, re.M)
        if len(versions) != 1:
            raise ValueError("unrecognized_hermes_version_output")
        return versions[0]

    def _build_config_yaml(self, model):
        config = yaml.safe_load(Hermes._build_config_yaml(model))
        config["model"] = {"default": model.removeprefix("openai/"), "provider": "custom",
                           "base_url": self.audit_upstream, "api_mode": "chat_completions",
                           "api_key": "${OPENAI_API_KEY}"}
        config["provider"] = "custom"
        config["agent"]["max_turns"] = 60
        return yaml.safe_dump(config, sort_keys=False)

    async def run(self, instruction, environment, context):
        # Harbor otherwise silently falls back to OpenRouter when the native
        # key is absent, contradicting the recorded endpoint/provider inputs.
        if not self.model_name or not self.model_name.startswith("openai/") or not os.environ.get("OPENAI_API_KEY"):
            raise ValueError("hermes_audit_requires_explicit_openai_model_and_key_no_fallback")
        # Hermes 0.19 no longer uses OPENAI_BASE_URL as its custom endpoint
        # configuration. Explicitly bind the native provider, canonical model
        # ID and env-referenced key; do not send Harbor's openai/ routing prefix
        # to a Fireworks-compatible endpoint or rely on provider auto-detection.
        if getattr(self, "mcp_servers", None) or getattr(self, "skills", None):
            raise ValueError("hermes_audit_custom_skills_or_mcp_not_qualified")
        instruction = self.render_instruction(instruction)
        model = self.model_name.split("/", 1)[1]
        env = {"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"],
               "OPENAI_BASE_URL": self.audit_upstream, "TERMINAL_ENV": "local",
               "HARBOR_INSTRUCTION": instruction}
        config = self._build_config_yaml(self.model_name)
        await self.exec_as_agent(environment, command=(
            "umask 077; mkdir -p /tmp/hermes; printf '%s' " + shlex.quote(config)
            + " > /tmp/hermes/config.yaml"), env=env, timeout_sec=10)
        command = 'hermes --yolo chat -q "$HARBOR_INSTRUCTION" -Q --provider custom --model ' + shlex.quote(model)
        toolsets = getattr(self, "_resolved_flags", {}).get("toolsets")
        if toolsets:
            command += " --toolsets " + shlex.quote(str(toolsets))
        try:
            await self.exec_as_agent(environment,
                command=command + " 2>&1 | stdbuf -oL tee /logs/agent/hermes.txt", env=env)
        finally:
            try:
                await self.exec_as_agent(environment,
                    # Hermes 0.19 sends --source through prune filters, which
                    # exclude rows with ended_at=NULL. One-shot CLI sessions
                    # can persist messages without setting ended_at. This home
                    # is fresh and job-isolated, so export all of it; retain
                    # the source/model/route and ambiguity checks below.
                    command="hermes sessions export /logs/agent/hermes-session.jsonl",
                    env={}, timeout_sec=30)
            except Exception:
                # Missing export stays observable and costs stay unknown. The
                # bound ledger's explicit policy controls later admission.
                pass

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
                    or type(row.get("api_call_count")) is not int or row["api_call_count"] <= 0):
                return
            pricing_source, pricing_version = row.get("cost_source"), row.get("pricing_version")
            source_name = "hermes_session_estimate"
            if row.get("cost_status") == "unknown":
                # The frozen runtime predates this exact model's price entry.
                # Price only this explicitly pinned standard-mode route from
                # Hermes' canonical, non-overlapping token buckets. Never
                # substitute the older deepseek-v4-pro model's rates.
                if (self.model_name != "openai/accounts/fireworks/models/deepseek-v4-pro-0813"
                        or self.audit_upstream != "https://api.fireworks.ai/inference/v1"
                        or row.get("service_tier") not in (None, "default", "standard")):
                    return
                buckets = [row.get(k) for k in ("input_tokens", "cache_read_tokens", "output_tokens", "cache_write_tokens")]
                if any(type(n) is not int or not 0 <= n <= 1_000_000_000 for n in buckets) or buckets[3] != 0:
                    return
                # https://docs.fireworks.ai/serverless/pricing, checked 2026-09-19.
                amount = float(sum(Decimal(n) * rate for n, rate in zip(buckets[:3],
                    (Decimal("1.32"), Decimal("0.044"), Decimal("3.96")))) / Decimal(1_000_000))
                pricing_source, pricing_version = "official_docs_snapshot", "fireworks-deepseek-v4-pro-0813-standard-2026-09-19"
                source_name = "native_usage_official_standard_price_estimate"
            elif row.get("cost_status") != "estimated":
                return
            if (pricing_source not in ("official_docs_snapshot", "provider_models_api")
                    or not isinstance(pricing_version, str) or not pricing_version
                    or type(amount) not in (int, float) or not math.isfinite(amount) or amount <= 0):
                return
            context.cost_usd = amount
            context.metadata = {**(context.metadata or {}), "iorec_native_cost": {
                "source": source_name, "cost_status": "estimated",
                "pricing_source": pricing_source, "pricing_version": pricing_version,
                "session_export_sha256": hashlib.sha256(raw).hexdigest(),
                "billing_verified": False,
                "scope": "native_single_cli_session_report_not_independent_billing_or_complete_auxiliary_spend"}}
        except (OSError, ValueError, TypeError, AttributeError):
            # Missing or unusable native cost remains None; the bound ledger's
            # explicit policy decides continuation. Do not guess pricing here.
            return

    async def exec_as_agent(self, environment, command, env=None, cwd=None, timeout_sec=None):
        return await super().exec_as_agent(environment, command,
            env={**(env or {}), "HERMES_HOME": "/tmp/hermes"}, cwd=cwd, timeout_sec=timeout_sec)
