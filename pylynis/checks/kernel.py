from __future__ import annotations

import platform

from .base import Check
from ..core.types import Finding, Severity


class KRNL_1000_KernelVersion(Check):
    id = "KRNL-1000"
    title = "Check kernel version"
    category = "KERNEL"
    tags = ["kernel", "version"]

    def run(self, ctx):  # type: ignore[override]
        version = platform.release()
        if version:
            return self.ok(notes=f"Kernel: {version}")
        f = Finding(id=self.id + ":unknown", description="Unable to determine kernel version", severity=Severity.WARNING)
        return self.fail([f])
