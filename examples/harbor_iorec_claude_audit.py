"""Pinned native Claude Code in the controlled Harbor pcap/TLS audit profile.

Uses the locally selected executable, not a floating curl/npm installation.
Only direct Anthropic-protocol HTTPS endpoints are supported by this profile.
"""
from harbor.agents.installed.claude_code import ClaudeCode
from harbor_iorec_audit_base import IorecAuditMixin


class IorecClaudeAudit(IorecAuditMixin, ClaudeCode):
    AUDIT_AGENT = "claude"
