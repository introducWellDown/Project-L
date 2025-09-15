from __future__ import annotations
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity

class SYSCTL_9000_IpForward(Check):
    id="SYSCTL-9000"; title="Check net.ipv4.ip_forward"; category="SYSCTL"
    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/ip_forward")
        if not path.exists(): return self.skip(notes="ip_forward not available")
        val = path.read_text().strip()
        if val=="0": return self.ok(notes="ip_forward disabled")
        f = Finding(id=self.id+":on", description="IP forwarding enabled", severity=Severity.SUGGESTION)
        return self.fail([f])
