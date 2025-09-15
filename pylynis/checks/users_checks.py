from __future__ import annotations
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity

class USERS_10000_RootUid(Check):
    id="USERS-10000"; title="Check for multiple UID 0 accounts"; category="USERS"
    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists(): return self.skip(notes="/etc/passwd not found")
        roots = [l for l in passwd.read_text(encoding="utf-8").splitlines() if l.split(":")[2]=="0"]
        if len(roots)>1:
            f = Finding(id=self.id+":multi", description=f"Multiple UID 0 accounts: {len(roots)}", severity=Severity.HIGH)
            return self.fail([f])
        return self.ok(notes="Only root has UID 0")
