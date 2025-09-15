from __future__ import annotations

import platform
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class KRNL_4000_KernelVersion(Check):
    id = "KRNL-4000"
    title = "Detect kernel version"
    category = "KRNL"

    def run(self, ctx):
        rel = platform.release()
        if rel:
            return self.ok(notes=f"Kernel version {rel}")
        f = Finding(id=self.id + ":unknown", description="Unable to determine kernel version", severity=Severity.SUGGESTION)
        return self.fail([f])


class KRNL_4001_CheckArch(Check):
    id = "KRNL-4001"
    title = "Check system architecture"
    category = "KRNL"

    def run(self, ctx):
        arch = platform.machine()
        if arch:
            return self.ok(notes=f"Architecture {arch}")
        return self.skip(notes="Unknown architecture")


class KRNL_4002_RandomizeVaSpace(Check):
    id = "KRNL-4002"
    title = "Check kernel.randomize_va_space"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/randomize_va_space")
        if not path.exists():
            return self.skip(notes="randomize_va_space not available")
        val = path.read_text().strip()
        if val in {"1", "2"}:
            return self.ok(notes=f"randomize_va_space={val}")
        f = Finding(id=self.id + ":disabled", description="ASLR disabled", severity=Severity.WARNING)
        return self.fail([f])


class KRNL_4003_SysRq(Check):
    id = "KRNL-4003"
    title = "Check kernel.sysrq"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/sysrq")
        if not path.exists():
            return self.skip(notes="sysrq not available")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="sysrq disabled")
        f = Finding(id=self.id + ":enabled", description=f"sysrq enabled ({val})", severity=Severity.SUGGESTION)
        return self.fail([f])


class KRNL_4004_DmesgRestrict(Check):
    id = "KRNL-4004"
    title = "Check kernel.dmesg_restrict"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/dmesg_restrict")
        if not path.exists():
            return self.skip(notes="dmesg_restrict not available")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="dmesg restricted")
        f = Finding(id=self.id + ":off", description="dmesg not restricted", severity=Severity.SUGGESTION)
        return self.fail([f])


class KRNL_4005_KptrRestrict(Check):
    id = "KRNL-4005"
    title = "Check kernel.kptr_restrict"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/kptr_restrict")
        if not path.exists():
            return self.skip(notes="kptr_restrict not available")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="kptr_restrict enabled")
        f = Finding(id=self.id + ":off", description="kptr_restrict disabled", severity=Severity.SUGGESTION)
        return self.fail([f])


class KRNL_4006_ModuleLoading(Check):
    id = "KRNL-4006"
    title = "Check kernel.modules_disabled"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/modules_disabled")
        if not path.exists():
            return self.skip(notes="modules_disabled not available")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="Module loading disabled")
        return self.ok(notes="Module loading enabled")
