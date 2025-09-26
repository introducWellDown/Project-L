from __future__ import annotations
import shutil, subprocess

from .base import Check
from ..core.types import Finding, Severity

def _svc_active(name: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    p = subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return p.stdout.strip() == "active"

class FirewallRunning(Check):
    id = "FW:running"
    title = "Межсетевой экран запущен"
    category = "FIREWALL"
    tags = ["firewalld","ufw"]

    def run(self, ctx):
        if _svc_active("firewalld") or _svc_active("ufw"):
            return self.ok()
        return self.fail([Finding(id=self.id+":stopped", description="firewalld/ufw не активен", severity=Severity.HIGH)])

class FirewallDefaultDeny(Check):
    id = "FW:default-deny"
    title = "Политика по умолчанию — deny/drop"
    category = "FIREWALL"

    def run(self, ctx):
        # firewalld: зона по умолчанию
        if shutil.which("firewall-cmd"):
            p = subprocess.run(["firewall-cmd","--get-default-zone"], stdout=subprocess.PIPE, text=True)
            zone = p.stdout.strip()
            # упростим: проверяем, что не 'trusted'
            if zone and zone != "trusted":
                return self.ok(notes=f"default-zone={zone}")
            return self.fail([Finding(id=self.id+":allow", description=f"default-zone={zone}", severity=Severity.WARNING)])
        # ufw
        if shutil.which("ufw"):
            p = subprocess.run(["ufw","status"], stdout=subprocess.PIPE, text=True)
            out = p.stdout.lower()
            if "status: active" in out and "default: deny" in out:
                return self.ok()
            return self.fail([Finding(id=self.id+":ufw", description="UFW не active или default не deny", severity=Severity.WARNING)])
        return self.skip("Ни firewalld, ни ufw не установлены")
