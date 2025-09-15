from __future__ import annotations
import platform
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity

class KRNL_4000_KernelVersion(Check):
    id="KRNL-4000"; title="Detect kernel version"; category="KRNL"
    def run(self, ctx):
        rel = platform.release()
        if rel: return self.ok(notes=f"Kernel version {rel}")
        f = Finding(id=self.id+":unknown", description="Unable to determine kernel version", severity=Severity.SUGGESTION)
        return self.fail([f])

class KRNL_4002_RandomizeVaSpace(Check):
    id="KRNL-4002"; title="Check kernel.randomize_va_space"; category="KRNL"
    def run(self, ctx):
        path = Path("/proc/sys/kernel/randomize_va_space")
        if not path.exists(): return self.skip(notes="randomize_va_space not available")
        val = path.read_text().strip()
        if val in {"1","2"}: return self.ok(notes=f"randomize_va_space={val}")
        f = Finding(id=self.id+":disabled", description="ASLR disabled", severity=Severity.WARNING)
        return self.fail([f])
