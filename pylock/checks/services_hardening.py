from __future__ import annotations
import shutil, subprocess

from .base import Check
from ..core.types import Finding, Severity

class NoLegacyServices(Check):
    id = "NET:no-legacy"
    title = "Отсутствуют устаревшие сетевые службы (telnet/ftp/rsync без auth)"
    category = "OTHER"

    def run(self, ctx):
        if shutil.which("ss"):
            p = subprocess.run(["ss","-lntup"], stdout=subprocess.PIPE, text=True)
            out = p.stdout.lower()
            for bad in ("telnet","in.telnetd","vsftpd","proftpd","pure-ftpd","tftp","in.tftpd"):
                if bad in out:
                    return self.fail([Finding(id=self.id+":legacy", description=f"Обнаружен {bad}", severity=Severity.HIGH)])
            return self.ok()
        return self.skip("ss недоступен")
