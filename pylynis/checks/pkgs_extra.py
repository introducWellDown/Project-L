from __future__ import annotations
import shutil
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd

class PKGS_6000_PackageManager(Check):
    id="PKGS-6000"; title="Detect package manager"; category="PKGS"
    def run(self, ctx):
        c = ["apt","apt-get","dnf","yum","zypper","pacman","apk","brew","port"]
        found = [x for x in c if shutil.which(x)]
        if found: return self.ok(notes=f"Available PMs: {', '.join(found)}")
        f = Finding(id=self.id+":none", description="No known package manager found", severity=Severity.WARNING)
        return self.fail([f])
