from __future__ import annotations

import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class BOOT_2000_GrubConfig(Check):
    id = "BOOT-2000"
    title = "Check GRUB configuration file"
    category = "BOOT"

    def run(self, ctx):
        grub_cfg = Path("/boot/grub/grub.cfg")
        if grub_cfg.exists():
            return self.ok(notes=f"Found grub.cfg at {grub_cfg}")
        grub2_cfg = Path("/boot/grub2/grub.cfg")
        if grub2_cfg.exists():
            return self.ok(notes=f"Found grub.cfg at {grub2_cfg}")
        f = Finding(id=self.id + ":missing", description="GRUB configuration not found", severity=Severity.WARNING)
        return self.fail([f])


class BOOT_2001_GrubPassword(Check):
    id = "BOOT-2001"
    title = "Check if GRUB password is set"
    category = "BOOT"

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
    id = "BOOT-2002"
    title = "Check for initramfs/initrd presence"
    category = "BOOT"

    def run(self, ctx):
        boot = Path("/boot")
        if not boot.exists():
            return self.skip(notes="/boot not present")
        imgs = list(boot.glob("initramfs-*")) + list(boot.glob("initrd-*"))
        if imgs:
            return self.ok(notes=f"Found {len(imgs)} initramfs/initrd images")
        f = Finding(id=self.id + ":none", description="No initramfs/initrd found in /boot", severity=Severity.WARNING)
        return self.fail([f])


class BOOT_2003_SecureBoot(Check):
    id = "BOOT-2003"
    title = "Check if Secure Boot is enabled (EFI)"
    category = "BOOT"

    def run(self, ctx):
        efivar = Path("/sys/firmware/efi/efivars")
        if not efivar.exists():
            return self.skip(notes="Not an EFI system")
        # Check variable SecureBoot-* value
        for p in efivar.glob("SecureBoot-*"):
            try:
                data = p.read_bytes()
                if data and data[-1] == 1:
                    return self.ok(notes="Secure Boot enabled")
                else:
                    f = Finding(id=self.id + ":off", description="Secure Boot disabled", severity=Severity.WARNING)
                    return self.fail([f])
            except Exception:
                continue
        return self.skip(notes="SecureBoot variable not found")


class BOOT_2004_BootloaderOwner(Check):
    id = "BOOT-2004"
    title = "Check bootloader directory ownership"
    category = "BOOT"

    def run(self, ctx):
        for path in [Path("/boot/grub"), Path("/boot/grub2")]:
            if path.exists():
                st = path.stat()
                if st.st_uid != 0:
                    f = Finding(id=self.id + ":owner", description=f"{path} not owned by root", severity=Severity.HIGH)
                    return self.fail([f])
                return self.ok(notes=f"{path} owned by root")
        return self.skip(notes="No grub directory found")


class BOOT_2005_BootMountPermissions(Check):
    id = "BOOT-2005"
    title = "Check /boot partition mount options"
    category = "BOOT"

    def run(self, ctx):
        try:
            mnt = Path("/proc/mounts").read_text(encoding="utf-8")
        except FileNotFoundError:
            return self.skip(notes="/proc/mounts not accessible")
        for line in mnt.splitlines():
            if " /boot " in line:
                opts = line.split()[3].split(",")
                if "nosuid" in opts and "nodev" in opts:
                    return self.ok(notes="/boot has nosuid,nodev")
                f = Finding(id=self.id + ":opts", description="/boot missing nosuid/nodev", severity=Severity.SUGGESTION)
                return self.fail([f])
        return self.skip(notes="/boot not mounted separately")
