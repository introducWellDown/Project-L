from __future__ import annotations
import os, shutil, subprocess

from .base import Check
from ..core.types import Finding, Severity

class LogrotatePresent(Check):
    id = "LOGGING:logrotate"
    title = "Настроена ротация логов (logrotate)"
    category = "LOGGING"

    def run(self, ctx):
        if os.path.isdir("/etc/logrotate.d"):
            return self.ok()
        return self.fail([Finding(id=self.id+":missing", description="/etc/logrotate.d отсутствует", severity=Severity.WARNING)])

class TimeSyncRunning(Check):
    id = "LOGGING:timesync"
    title = "Синхронизация времени активна"
    category = "LOGGING"

    def run(self, ctx):
        for svc in ("chronyd","systemd-timesyncd","ntpd"):
            p = subprocess.run(["bash","-lc", f"systemctl is-active {svc}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if p.stdout.strip()=="active":
                return self.ok(notes=svc)
        return self.fail([Finding(id=self.id+":inactive", description="Сервис синхронизации времени не активен", severity=Severity.WARNING)])
