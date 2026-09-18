"""Pinned native Codex in the controlled Harbor pcap/TLS audit profile."""
from harbor.agents.installed.codex import Codex
from harbor_iorec_audit_base import IorecAuditMixin


class IorecCodexAudit(IorecAuditMixin, Codex):
    AUDIT_AGENT = "codex"
