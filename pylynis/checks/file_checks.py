from __future__ import annotations
import os
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity

class FILE_3000_EtcHostsPermissions(Check):
    id="FILE-3000"; title="Check /etc/hosts permissions"; category="FILE"
    def run(self, ctx):
        p = Path("/etc/hosts")
        if not p.exists(): return self.skip(notes="/etc/hosts missing")
        if p.stat().st_mode & 0o022:
            f = Finding(id=self.id+":perm", description="/etc/hosts is group/world-writable", severity=Severity.WARNING)
            return self.fail([f])
        return self.ok(notes="/etc/hosts permissions OK")

class FILE_3001_TmpPermissions(Check):
    id="FILE-3001"; title="Check /tmp sticky bit"; category="FILE"
    def run(self, ctx):
        tmp = Path("/tmp")
        if not tmp.exists(): return self.skip(notes="/tmp not present")
        if tmp.stat().st_mode & 0o1000: return self.ok(notes="/tmp has sticky bit set")
        f = Finding(id=self.id+":sticky", description="/tmp missing sticky bit", severity=Severity.WARNING)
        return self.fail([f])
