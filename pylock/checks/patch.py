from __future__ import annotations
import shutil, subprocess

from .base import Check
from ..core.types import Finding, Severity

class SecurityUpdates(Check):
    id = "PATCH:security-updates"
    title = "Доступны ли необновлённые security-патчи"
    category = "PATCH"

    def run(self, ctx):
        # Debian/Ubuntu
        if shutil.which("apt"):
            p = subprocess.run(["apt","list","--upgradable"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            up = [l for l in p.stdout.splitlines() if "security" in l.lower()]
            if up:
                return self.fail([Finding(id=self.id+":pending", description=f"Доступны security-обновления: {len(up)}", severity=Severity.WARNING)])
            return self.ok()
        # RHEL/CentOS
        if shutil.which("yum"):
            p = subprocess.run(["yum","check-update","--security","-q"], stdout=subprocess.PIPE, text=True)
            out = p.stdout.strip()
            if out:
                return self.fail([Finding(id=self.id+":pending", description="Есть security-обновления (yum)", severity=Severity.WARNING)])
            return self.ok()
        return self.skip("Неизвестный пакетный менеджер")
