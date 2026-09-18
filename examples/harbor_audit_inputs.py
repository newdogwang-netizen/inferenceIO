"""One source of truth for files uploaded by controlled native CLI profiles.

This module is intentionally standard-library-only: preflight can inspect the
inputs without importing or executing Harbor or an agent. The caller must keep
the private key out of public provenance reports.
"""
from pathlib import Path
import ipaddress
import re
import shlex
from urllib.parse import urlsplit

AGENTS = {
    "codex": {"provider": "openai", "upstream": "https://api.openai.com/v1",
              "profile": "harbor_iorec_codex_audit:IorecCodexAudit"},
    "claude": {"provider": "anthropic", "upstream": "https://api.anthropic.com",
               "profile": "harbor_iorec_claude_audit:IorecClaudeAudit"},
}


def upstream_url(value: str) -> str:
    """Transparent task networking requires a non-loopback HTTPS endpoint."""
    try:
        u = urlsplit(value)
        host = u.hostname or ""
        valid = (u.scheme == "https" and not u.username and not u.password
                 and not u.query and not u.fragment and (u.port is None or 1 <= u.port <= 65535)
                 and re.fullmatch(r"[A-Za-z0-9.-]+", host)
                 and host.lower() != "localhost" and not host.lower().endswith(".localhost")
                 and re.fullmatch(r"[/A-Za-z0-9_.~-]*", u.path)
                 and not any(part in (".", "..") for part in u.path.split("/"))
                 and not any(c.isspace() for c in value))
        try:
            valid = valid and ipaddress.ip_address(host).is_global
        except ValueError:
            pass
        if not valid:
            raise ValueError()
    except ValueError:
        raise ValueError("audit_requires_non_loopback_https_upstream") from None
    return value.rstrip("/")


def codex_uploads(*, codex: Path, iorec: Path, key: Path,
                  code_mode: Path | None = None, unshare: Path | None = None,
                  nsenter: Path | None = None) -> dict[Path, str]:
    return native_uploads(agent="codex", executable=codex, iorec=iorec, key=key,
                          code_mode=code_mode, unshare=unshare, nsenter=nsenter)


def native_uploads(*, agent: str, executable: Path, iorec: Path, key: Path,
                   code_mode: Path | None = None, unshare: Path | None = None,
                   nsenter: Path | None = None) -> dict[Path, str]:
    if agent not in AGENTS:
        raise ValueError("unsupported_native_audit_agent")
    examples = Path(__file__).resolve().parent
    executable = executable.resolve(strict=True)
    inputs = [
        (executable, "/opt/iorec-agent/" + agent),
        (iorec, "/tmp/iorec-bin"),
        (key, "/tmp/iorec.key"),
        (unshare or Path("/usr/bin/unshare"), "/tmp/iorec-runtime/unshare"),
        (nsenter or Path("/usr/bin/nsenter"), "/tmp/iorec-runtime/nsenter"),
        (examples / "harbor-audit-unshare", "/usr/bin/unshare"),
        (examples / "harbor-audit-nsenter", "/usr/bin/nsenter"),
    ]
    if agent == "codex":
        inputs.append((code_mode or executable.with_name("codex-code-mode-host"),
                       "/opt/iorec-agent/codex-code-mode-host"))
    else:
        inputs.append((examples / "harbor-audit-claude-hook-probe", "/opt/iorec-agent/claude-hook-probe"))
    for name in ("ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libgcc_s.so.1",
                 "libselinux.so.1", "libpcre2-8.so.0"):
        inputs.append((Path("/lib/x86_64-linux-gnu") / name, "/tmp/iorec-runtime/" + name))
    result = {path.resolve(strict=True): remote for path, remote in inputs}
    if len(result) != len(inputs):
        raise ValueError("audit_upload_sources_must_be_distinct")
    return result


def cli_wrapper(agent: str, upstream: str) -> str:
    """Fixed executable boundary: prompt strings are never searched/replaced."""
    if agent not in AGENTS:
        raise ValueError("unsupported_native_audit_agent")
    upstream = upstream_url(upstream)
    cli = "/opt/iorec-agent/" + agent
    flags = ["run", "--runs-dir", "/logs/agent/iorec-runs", "--upstream", upstream,
             "--provider", AGENTS[agent]["provider"], "--adapter", agent, "--body", "full",
             "--event-log-format", "zstd-blocks", "--max-event-storage-bytes", "536870912",
             "--max-run-blob-storage-bytes", "536870912", "--pcap-max-bytes", "536870912",
             "--key-file", "/tmp/iorec.key", "--tls-keylog", "--pcap", "--task-netns",
             "--transparent-proxy", "--", cli]
    prefix = "#!/bin/bash\nset -euo pipefail\n"
    if agent == "claude":
        prefix += "export DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1\n"
    prefix += ('if [ "$#" -eq 1 ]; then\n'
               '  case "$1" in --version|-v|-V|--help|-h) exec ' + shlex.quote(cli) + ' "$@" ;; esac\n'
               'fi\n')
    # Claude hooks use current_exe() to re-enter the recorder. Explicitly
    # invoking ld.so makes that path point to the loader instead of iorec.
    # Require a natively runnable recorder for Claude; setup checks this before
    # any model run. Codex has no recorder self-exec hook in this profile.
    launcher = ("/tmp/iorec-runtime/ld-linux-x86-64.so.2 --library-path /tmp/iorec-runtime /tmp/iorec-bin"
                if agent == "codex" else "/tmp/iorec-bin")
    return prefix + "exec " + launcher + " " + shlex.join(flags) + ' "$@"\n'
