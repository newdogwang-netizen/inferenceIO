"""Shared installation/confinement for controlled, pinned native agent CLIs."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import tempfile

from harbor_audit_inputs import AGENTS, cli_wrapper, native_uploads, upstream_url

EXAMPLES = Path(__file__).resolve().parent


def host_path(variable, default):
    return Path(os.environ.get(variable, str(default))).expanduser().resolve(strict=True)


class IorecAuditMixin:
    """Wrap a selected CLI, not arbitrary text in Harbor's shell commands.

    The outer disposable container is privileged; the actual agent is not.
    This profile does not qualify other providers, auxiliary egress, or ACP.
    """
    AUDIT_AGENT = ""

    def __init__(self, *args, **kwargs):
        self.audit_upstream = upstream_url(os.environ.get(
            "IOREC_HARBOR_UPSTREAM", AGENTS[self.AUDIT_AGENT]["upstream"]))
        extra = dict(kwargs.pop("extra_env", None) or {})
        # Bind Harbor's model resolver and the recorder to the same endpoint.
        name = "ANTHROPIC_BASE_URL" if self.AUDIT_AGENT == "claude" else "OPENAI_BASE_URL"
        extra[name] = self.audit_upstream
        if self.AUDIT_AGENT == "claude":
            if any(os.environ.get(k) for k in ("CLAUDE_CODE_USE_BEDROCK", "AWS_BEARER_TOKEN_BEDROCK",
                                               "CLAUDE_CODE_USE_VERTEX")):
                raise ValueError("audit_claude_requires_direct_anthropic_protocol")
        super().__init__(*args, extra_env=extra, **kwargs)

    def audit_uploads(self):
        agent = self.AUDIT_AGENT
        executable = host_path("IOREC_HARBOR_" + agent.upper() + "_BIN",
                               shutil.which(agent) or "/missing/" + agent)
        return native_uploads(
            agent=agent, executable=executable,
            iorec=host_path("IOREC_HARBOR_BIN", EXAMPLES.parent / "target/release/iorec"),
            key=host_path("IOREC_HARBOR_KEY_FILE", "/tmp/iorec-tbench/master.key"),
            code_mode=(host_path("IOREC_HARBOR_CODE_MODE_BIN", executable.with_name("codex-code-mode-host"))
                       if agent == "codex" else None),
            unshare=host_path("IOREC_HARBOR_UNSHARE_BIN", "/usr/bin/unshare"),
            nsenter=host_path("IOREC_HARBOR_NSENTER_BIN", "/usr/bin/nsenter"))

    async def install(self, environment):
        uploads = self.audit_uploads()
        await self.exec_as_root(environment, command=(
            "set -eu; export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update && apt-get install -y --no-install-recommends "
            "bash ca-certificates iproute2 nftables procps slirp4netns tcpdump uidmap util-linux; "
            "if ! id -u iorecagent >/dev/null 2>&1; then useradd -m -u 10001 -s /bin/bash iorecagent; fi; "
            "test $(id -u iorecagent) -eq 10001; test $(id -g iorecagent) -eq 10001; "
            "usermod --add-subuids 100000-165535 iorecagent; "
            "usermod --add-subgids 100000-165535 iorecagent; "
            "mkdir -p /tmp/iorec-runtime /opt/iorec-agent /logs/agent/iorec-runs /usr/local/bin"
        ), timeout_sec=300)
        for local, remote in uploads.items():
            await environment.upload_file(local, remote)
        with tempfile.TemporaryDirectory(prefix="iorec-harbor-wrapper-") as temp:
            wrapper = Path(temp) / self.AUDIT_AGENT
            wrapper.write_text(cli_wrapper(self.AUDIT_AGENT, self.audit_upstream))
            wrapper.chmod(0o600)
            await environment.upload_file(wrapper, "/usr/local/bin/" + self.AUDIT_AGENT)
        destinations = [remote for remote in uploads.values() if remote != "/tmp/iorec.key"]
        destinations += ["/usr/local/bin/" + self.AUDIT_AGENT, "/tmp/iorec-runtime", "/opt/iorec-agent"]
        quoted = shlex.join(destinations)
        await self.exec_as_root(environment, command=(
            "set -eu; chown -R 10001:10001 /app /logs/agent; "
            "chown root:root " + quoted + "; chmod 755 " + quoted + "; "
            "chmod 644 /tmp/iorec-runtime/lib*.so*; "
            "chown 10001:10001 /tmp/iorec.key; chmod 600 /tmp/iorec.key; "
            "dpkg-query -W -f='${Package}\t${Version}\n' > /logs/agent/audit-package-inventory.tsv; "
            'sha256sum "$(command -v tcpdump)" "$(command -v nft)" "$(command -v slirp4netns)" '
            '"$(command -v newuidmap)" "$(command -v newgidmap)" > /logs/agent/audit-tool-sha256.txt; '
            "/tmp/iorec-runtime/ld-linux-x86-64.so.2 --library-path /tmp/iorec-runtime /tmp/iorec-bin --version"
        ), timeout_sec=30)
        await self.prepare_agent_runtime(environment)
        await self.exec_as_agent(environment, command="/usr/local/bin/" + self.AUDIT_AGENT + " --version", timeout_sec=30)
        if self.AUDIT_AGENT == "claude":
            # Fail during setup, before paid inference, if this container cannot
            # execute the recorder and its lifecycle self-exec hook natively.
            await self.exec_as_agent(environment, command=(
                "/tmp/iorec-bin --version && /tmp/iorec-bin run "
                "--runs-dir /logs/agent/iorec-preflight --adapter claude --provider anthropic "
                "--body metadata-only --key-file /tmp/iorec.key --upstream "
                + shlex.quote(self.audit_upstream) + " -- /opt/iorec-agent/claude-hook-probe"
            ), timeout_sec=30)

    async def prepare_agent_runtime(self, environment):
        """Profiles with an installed runtime override this before CLI probes."""

    async def exec_as_agent(self, environment, command, env=None, cwd=None, timeout_sec=None):
        agent_env = {**(env or {}), "HOME": "/home/iorecagent", "USER": "iorecagent", "LOGNAME": "iorecagent"}
        # Some Harbor agents construct per-call env directly from os.environ;
        # never let it override the endpoint bound in the input manifest.
        provider_url = "ANTHROPIC_BASE_URL" if self.AUDIT_AGENT == "claude" else "OPENAI_BASE_URL"
        agent_env[provider_url] = self.audit_upstream
        if self.AUDIT_AGENT == "claude":
            agent_env.update(DISABLE_AUTOUPDATER="1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
        inner = shlex.quote("set -o pipefail; " + command)
        return await super().exec_as_agent(environment,
            command="exec /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups /bin/bash -c " + inner,
            env=agent_env, cwd=cwd, timeout_sec=timeout_sec)
