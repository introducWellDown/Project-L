from __future__ import annotations
import shutil, subprocess, os

from .base import Check
from ..core.types import Finding, Severity

class AuditdRunning(Check):
    id = "AUDIT:running"
    title = "auditd запущен"
    category = "AUDIT"

    def run(self, ctx):
        if not shutil.which("systemctl"):
            return self.skip("systemctl недоступен")
        p = subprocess.run(["systemctl","is-active","auditd"], stdout=subprocess.PIPE, text=True)
        if p.stdout.strip()=="active":
            return self.ok()
        return self.fail([Finding(id=self.id+":stopped", description="auditd не активен", severity=Severity.HIGH)])

class AuditRulesPresent(Check):
    id = "AUDIT:rules"
    title = "Базовые правила аудита присутствуют"
    category = "AUDIT"

    def run(self, ctx):
        if shutil.which("auditctl"):
            p = subprocess.run(["auditctl","-l"], stdout=subprocess.PIPE, text=True)
            lines = [l for l in p.stdout.splitlines() if l.strip()]
            if len(lines)>=5:
                return self.ok(notes=f"{len(lines)} правил")
            return self.fail([Finding(id=self.id+":empty", description="Правила аудита пустые/минимальные", severity=Severity.WARNING)])
        # RHEL/Ubuntu могут хранить правила в /etc/audit/*
        for d in ("/etc/audit","/etc/audit/rules.d"):
            if os.path.isdir(d) and any(fn.endswith(".rules") for fn in os.listdir(d)):
                return self.ok(notes=f"rules in {d}")
        return self.skip("auditctl/конфиг не найден")
