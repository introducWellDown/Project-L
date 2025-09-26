from __future__ import annotations
import shutil, os

from .base import Check
from ..core.types import Finding, Severity

class AideInstalled(Check):
    id = "FIM:aide-installed"
    title = "AIDE установлен"
    category = "FIM"

    def run(self, ctx):
        if shutil.which("aide"):
            return self.ok()
        return self.fail([Finding(id=self.id+":missing", description="AIDE не установлен", severity=Severity.WARNING)])

class AideInitialized(Check):
    id = "FIM:aide-initialized"
    title = "AIDE база инициализирована"
    category = "FIM"

    def run(self, ctx):
        for p in ("/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz"):
            if os.path.exists(p):
                return self.ok()
        return self.fail([Finding(id=self.id+":db-missing", description="База AIDE не найдена", severity=Severity.WARNING)])
