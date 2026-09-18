"""One source of truth for files uploaded by the controlled Codex profile.

This module is intentionally standard-library-only: preflight can inspect the
inputs without importing or executing Harbor or an agent. The caller must keep
the private key out of public provenance reports.
"""
from pathlib import Path


def codex_uploads(*, codex: Path, iorec: Path, key: Path,
                  code_mode: Path | None = None, unshare: Path | None = None,
                  nsenter: Path | None = None) -> dict[Path, str]:
    examples = Path(__file__).resolve().parent
    codex = codex.resolve(strict=True)
    inputs = [
        (codex, "/usr/local/bin/codex"),
        (code_mode or codex.with_name("codex-code-mode-host"), "/usr/local/bin/codex-code-mode-host"),
        (iorec, "/tmp/iorec-bin"),
        (key, "/tmp/iorec.key"),
        (unshare or Path("/usr/bin/unshare"), "/tmp/iorec-runtime/unshare"),
        (nsenter or Path("/usr/bin/nsenter"), "/tmp/iorec-runtime/nsenter"),
        (examples / "harbor-audit-unshare", "/usr/bin/unshare"),
        (examples / "harbor-audit-nsenter", "/usr/bin/nsenter"),
    ]
    for name in ("ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libgcc_s.so.1",
                 "libselinux.so.1", "libpcre2-8.so.0"):
        inputs.append((Path("/lib/x86_64-linux-gnu") / name, "/tmp/iorec-runtime/" + name))
    result = {path.resolve(strict=True): remote for path, remote in inputs}
    if len(result) != len(inputs):
        raise ValueError("audit_upload_sources_must_be_distinct")
    return result
