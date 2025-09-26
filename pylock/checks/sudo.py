from __future__ import annotations
import os, re

from .base import Check
from ..core.types import Finding, Severity

class SudoNoNopasswd(Check):
    id = "SUDO:nopasswd"
    title = "Отсутствуют широкие NOPASSWD в sudoers"
    category = "AUTH"

    def run(self, ctx):
        paths = ["/etc/sudoers", "/etc/sudoers.d"]
        bad = []
        for p in paths:
            if os.path.isfile(p):
                bad += re.findall(r"^.*NOPASSWD:.*$", open(p,"r",encoding="utf-8",errors="ignore").read(), re.M)
            elif os.path.isdir(p):
                for fn in os.listdir(p):
                    fp = os.path.join(p,fn)
                    if os.path.isfile(fp):
                        bad += re.findall(r"^.*NOPASSWD:.*$", open(fp,"r",encoding="utf-8",errors="ignore").read(), re.M)
        if bad:
            return self.fail([Finding(id=self.id+":present", description="Обнаружены NOPASSWD в sudoers", severity=Severity.WARNING)])
        return self.ok()
