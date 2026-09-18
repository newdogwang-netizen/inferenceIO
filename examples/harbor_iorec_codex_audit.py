"""Harbor Codex agent instrumented with iorec transport evidence.

This is intended for controlled, local audit runs. The outer Harbor container
uses ``harbor-audit-compose.yaml`` so iorec can create a nested user/network
namespace. The actual Codex process runs as UID 10001 with no capabilities and
``no_new_privs`` inside that namespace.
"""

import os
import shlex
import shutil
from pathlib import Path
from typing import Any, override

from harbor.agents.installed.codex import Codex
from harbor.environments.base import BaseEnvironment
from harbor_audit_inputs import codex_uploads


_EXAMPLES_DIR = Path(__file__).resolve().parent


def _host_path(variable: str, default: str | Path) -> Path:
    return Path(os.environ.get(variable, str(default))).expanduser().resolve()


class IorecCodexAudit(Codex):
    """Run the real Codex CLI behind iorec pcap/TLS capture in Harbor."""

    _AGENT_UID = 10001
    _AGENT_GID = 10001
    _SUBORDINATE_START = 100000
    _SUBORDINATE_COUNT = 65536

    _HOST_CODEX = _host_path(
        "IOREC_HARBOR_CODEX_BIN", shutil.which("codex") or "/usr/local/bin/codex"
    )
    _HOST_CODE_MODE = _host_path(
        "IOREC_HARBOR_CODE_MODE_BIN", _HOST_CODEX.with_name("codex-code-mode-host")
    )
    _HOST_IOREC = _host_path(
        "IOREC_HARBOR_BIN", _EXAMPLES_DIR.parent / "target/release/iorec"
    )
    _HOST_KEY = _host_path(
        "IOREC_HARBOR_KEY_FILE", "/tmp/iorec-tbench/master.key"
    )
    _HOST_UNSHARE = _host_path("IOREC_HARBOR_UNSHARE_BIN", "/usr/bin/unshare")
    _HOST_NSENTER = _host_path("IOREC_HARBOR_NSENTER_BIN", "/usr/bin/nsenter")

    _UPLOADS = codex_uploads(codex=_HOST_CODEX, code_mode=_HOST_CODE_MODE,
                            iorec=_HOST_IOREC, key=_HOST_KEY,
                            unshare=_HOST_UNSHARE, nsenter=_HOST_NSENTER)

    @override
    async def install(self, environment: BaseEnvironment) -> None:
        missing = [str(path) for path in self._UPLOADS if not path.is_file()]
        if missing:
            raise FileNotFoundError("missing Harbor audit inputs: " + ", ".join(missing))

        await self.exec_as_root(
            environment,
            command=(
                "set -eu; export DEBIAN_FRONTEND=noninteractive; "
                "apt-get update && apt-get install -y --no-install-recommends "
                "bash ca-certificates iproute2 nftables procps slirp4netns "
                "tcpdump uidmap util-linux; "
                "if ! id -u iorecagent >/dev/null 2>&1; then "
                f"useradd -m -u {self._AGENT_UID} -s /bin/bash iorecagent; fi; "
                f"usermod --add-subuids {self._SUBORDINATE_START}-"
                f"{self._SUBORDINATE_START + self._SUBORDINATE_COUNT - 1} iorecagent; "
                f"usermod --add-subgids {self._SUBORDINATE_START}-"
                f"{self._SUBORDINATE_START + self._SUBORDINATE_COUNT - 1} iorecagent; "
                "mkdir -p /tmp/iorec-runtime /logs/agent/iorec-runs /usr/local/bin"
            ),
            timeout_sec=300,
        )

        for local_path, remote_path in self._UPLOADS.items():
            await environment.upload_file(local_path, remote_path)

        await self.exec_as_root(
            environment,
            command=(
                "chown -R 10001:10001 /app /logs/agent; "
                "chown root:root /tmp/iorec-bin /usr/local/bin/codex "
                "/usr/local/bin/codex-code-mode-host /usr/bin/unshare "
                "/usr/bin/nsenter /tmp/iorec-runtime/*; "
                "chmod 755 /tmp/iorec-bin /usr/local/bin/codex "
                "/usr/local/bin/codex-code-mode-host /usr/bin/unshare "
                "/usr/bin/nsenter /tmp/iorec-runtime/ld-linux-x86-64.so.2 "
                "/tmp/iorec-runtime/unshare /tmp/iorec-runtime/nsenter; "
                "chmod 644 /tmp/iorec-runtime/lib*.so*; "
                "chown 10001:10001 /tmp/iorec.key; chmod 600 /tmp/iorec.key; "
                "/usr/local/bin/codex --version; "
                "/tmp/iorec-runtime/ld-linux-x86-64.so.2 "
                "--library-path /tmp/iorec-runtime /tmp/iorec-bin --version"
            ),
        )

    @override
    async def exec_as_agent(
        self,
        environment: BaseEnvironment,
        command: str,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout_sec: int | None = None,
    ) -> Any:
        marker = "codex exec "
        if marker in command:
            recorder = (
                "/tmp/iorec-runtime/ld-linux-x86-64.so.2 "
                "--library-path /tmp/iorec-runtime /tmp/iorec-bin run "
                "--runs-dir /logs/agent/iorec-runs "
                "--upstream https://api.openai.com/v1 "
                "--provider openai --adapter codex --body full "
                "--event-log-format zstd-blocks "
                "--max-event-storage-bytes 536870912 "
                "--max-run-blob-storage-bytes 536870912 "
                "--pcap-max-bytes 536870912 "
                "--key-file /tmp/iorec.key --tls-keylog --pcap "
                "--task-netns --transparent-proxy -- codex exec "
            )
            command = command.replace(marker, recorder, 1)

        agent_env = {
            "HOME": "/home/iorecagent",
            "USER": "iorecagent",
            "LOGNAME": "iorecagent",
            **(env or {}),
        }
        inner = shlex.quote("set -o pipefail; " + command)
        confined_command = (
            f"exec /usr/bin/setpriv --reuid={self._AGENT_UID} "
            f"--regid={self._AGENT_GID} --clear-groups /bin/bash -c {inner}"
        )
        return await super().exec_as_agent(
            environment,
            command=confined_command,
            env=agent_env,
            cwd=cwd,
            timeout_sec=timeout_sec,
        )
