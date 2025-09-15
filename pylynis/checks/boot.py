from __future__ import annotations
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity

class BOOT_2000_GrubConfig(Check):
    id = "BOOT-2000"; title = "Check GRUB configuration file"; category = "BOOT"
    def run(self, ctx):
        for p in (Path("/boot/grub/grub.cfg"), Path("/boot/grub2/grub.cfg")):
            if p.exists():
                return self.ok(notes=f"Found grub.cfg at {p}")
        f = Finding(id=self.id + ":missing", description="GRUB configuration not found", severity=Severity.WARNING)
        return self.fail([f])

class BOOT_2001_GrubPassword(Check):
    id = "BOOT-2001"; title = "Check if GRUB password is set"; category = "BOOT"
    def run(self, ctx):
        for candidate in [Path("/boot/grub/grub.cfg"), Path("/boot/grub2/grub.cfg")]:
            if candidate.exists():
                data = candidate.read_text(encoding="utf-8", errors="ignore")
                if "set superusers" in data and "password" in data:
                    return self.ok(notes="GRUB password configured")
                f = Finding(id=self.id + ":nopass", description="No GRUB password found", severity=Severity.WARNING)
                return self.fail([f])
        return self.skip(notes="No GRUB config to check")

class BOOT_2002_Initramfs(Check):
    id = "BOOT-2002"; title = "Check for initramfs/initrd presence"; category = "BOOT"
    def run(self, ctx):
        boot = Path("/boot")
        if not boot.exists(): return self.skip(notes="/boot not present")
        imgs = list(boot.glob("initramfs-*")) + list(boot.glob("initrd-*"))
        if imgs: return self.ok(notes=f"Found {len(imgs)} initramfs/initrd images")
        f = Finding(id=self.id + ":none", description="No initramfs/initrd found in /boot", severity=Severity.WARNING)
        return self.fail([f])
