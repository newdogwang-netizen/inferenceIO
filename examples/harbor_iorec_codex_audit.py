"""Pinned native Codex in the controlled Harbor pcap/TLS audit profile."""
import shlex

from harbor.agents.installed.codex import Codex
from harbor_iorec_audit_base import IorecAuditMixin


class IorecCodexAudit(IorecAuditMixin, Codex):
    AUDIT_AGENT = "codex"

    async def _upload_effective_config(self, environment, config, remote_path):
        # Harbor's environment user is root/None; this profile separately
        # confines Codex to UID 10001. Uploads retain private host permissions,
        # so Harbor's conditional default-user chown does not cover our user.
        expected = (self._REMOTE_CODEX_HOME / "config.toml").as_posix()
        if remote_path != expected:
            raise ValueError("unexpected_codex_config_destination")
        await super()._upload_effective_config(environment, config, remote_path)
        if config:
            path = shlex.quote(remote_path)
            await self.exec_as_root(environment, command=(
                f"test -f {path} && test ! -L {path} && "
                f"chown 10001:10001 {path} && chmod 600 {path}"
            ))
