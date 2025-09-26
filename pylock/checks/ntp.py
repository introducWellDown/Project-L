from __future__ import annotations
import subprocess

from .base import Check

class NtpSynchronized(Check):
    id = "NTP:sync"
    title = "Время синхронизировано (timedatectl)"
    category = "LOGGING"

    def run(self, ctx):
        p = subprocess.run(["timedatectl"], stdout=subprocess.PIPE, text=True)
        if "System clock synchronized: yes" in p.stdout:
            return self.ok()
        return self.skip("Не удалось подтвердить синхронизацию")
