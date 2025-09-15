from __future__ import annotations
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity

class SSH_8000_SshdConfigExists(Check):
    id="SSH-8000"; title="Check if sshd_config exists"; category="SSH"
    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if p.exists(): return self.ok(notes="sshd_config found")
        return self.fail([Finding(id=self.id+":missing", description="sshd_config not found", severity=Severity.WARNING)])
