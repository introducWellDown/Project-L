from __future__ import annotations

import shutil

from .base import Check
from ..core.types import Finding, Severity


class PKGS_1000_Manager(Check):
    id = "PKGS-1000"
    title = "Check package manager availability"
    category = "PACKAGES"
    tags = ["pkg", "manager"]

    def run(self, ctx):  # type: ignore[override]
        managers = ["apt", "dnf", "yum", "zypper", "pacman"]
        found = [m for m in managers if shutil.which(m)]
        if found:
            return self.ok(notes=f"Available: {', '.join(found)}")
        f = Finding(id=self.id+":missing", description="No package manager found", severity=Severity.ERROR)
        return self.fail([f])
