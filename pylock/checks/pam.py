from __future__ import annotations
import os, re

from .base import Check
from ..core.types import Finding, Severity

class PamPwquality(Check):
    id = "PAM:pwquality"
    title = "Включены требования сложности пароля (pam_pwquality)"
    category = "AUTH"

    def run(self, ctx):
        path = "/etc/pam.d/system-auth" if os.path.exists("/etc/pam.d/system-auth") else "/etc/pam.d/common-password"
        if not os.path.exists(path):
            return self.skip("PAM policy не найдена")
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
        if "pam_pwquality.so" in txt:
            return self.ok()
        return self.fail([Finding(id=self.id+":missing", description="pam_pwquality не включён", severity=Severity.WARNING)])

class PamFaillock(Check):
    id = "PAM:faillock"
    title = "Блокировка при подборе пароля (pam_faillock/pam_tally2)"
    category = "AUTH"

    def run(self, ctx):
        files = ["/etc/pam.d/system-auth","/etc/pam.d/password-auth","/etc/pam.d/common-auth"]
        found = False
        for f in files:
            if os.path.exists(f):
                t = open(f,"r",encoding="utf-8",errors="ignore").read()
                if "pam_faillock.so" in t or "pam_tally2.so" in t:
                    found = True
        if found:
            return self.ok()
        return self.fail([Finding(id=self.id+":missing", description="Нет pam_faillock/pam_tally2", severity=Severity.WARNING)])
