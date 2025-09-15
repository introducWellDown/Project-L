from __future__ import annotations

import os
import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class AUTH_1000_SudoVersion(Check):
    id = "AUTH-1000"
    title = "Check sudo availability and version"
    category = "AUTH"

    def run(self, ctx):
        exe = shutil.which("sudo")
        if not exe:
            f = Finding(id=self.id + ":missing", description="sudo not found", severity=Severity.WARNING)
            return self.fail([f])
        proc = run_cmd([exe, "--version"], check=False)
        if proc.returncode == 0:
            return self.ok(notes=f"Sudo version {proc.stdout.splitlines()[0]}")
        f = Finding(id=self.id + ":err", description="Unable to run sudo", severity=Severity.WARNING)
        return self.fail([f])


class AUTH_1001_SuBinary(Check):
    id = "AUTH-1001"
    title = "Check su binary availability"
    category = "AUTH"

    def run(self, ctx):
        exe = shutil.which("su")
        if exe:
            return self.ok(notes=f"Found su at {exe}")
        f = Finding(id=self.id + ":missing", description="su not found", severity=Severity.WARNING)
        return self.fail([f])


class AUTH_1002_ShadowPermissions(Check):
    id = "AUTH-1002"
    title = "Check /etc/shadow permissions"
    category = "AUTH"

    def run(self, ctx):
        shadow = Path("/etc/shadow")
        if not shadow.exists():
            f = Finding(id=self.id + ":missing", description="/etc/shadow not found", severity=Severity.WARNING)
            return self.fail([f])
        st = shadow.stat()
        if st.st_mode & 0o077:
            f = Finding(id=self.id + ":perm", description="/etc/shadow has overly permissive mode", severity=Severity.HIGH)
            return self.fail([f])
        return self.ok(notes="/etc/shadow permissions OK")


class AUTH_1003_PasswdPermissions(Check):
    id = "AUTH-1003"
    title = "Check /etc/passwd permissions"
    category = "AUTH"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            f = Finding(id=self.id + ":missing", description="/etc/passwd not found", severity=Severity.WARNING)
            return self.fail([f])
        st = passwd.stat()
        if st.st_mode & 0o022:
            f = Finding(id=self.id + ":perm", description="/etc/passwd is world-writable", severity=Severity.HIGH)
            return self.fail([f])
        return self.ok(notes="/etc/passwd permissions OK")


class AUTH_1004_PamDDirectory(Check):
    id = "AUTH-1004"
    title = "Check /etc/pam.d directory"
    category = "AUTH"

    def run(self, ctx):
        pamd = Path("/etc/pam.d")
        if pamd.exists() and pamd.is_dir():
            return self.ok(notes="/etc/pam.d exists")
        f = Finding(id=self.id + ":missing", description="/etc/pam.d directory missing", severity=Severity.WARNING)
        return self.fail([f])


class AUTH_1005_SshKeysPermissions(Check):
    id = "AUTH-1005"
    title = "Check for permissive SSH authorized_keys files"
    category = "AUTH"

    def run(self, ctx):
        home = Path("/home")
        bad: list[Finding] = []
        if not home.exists():
            return self.ok(notes="/home not found")
        for userdir in home.iterdir():
            ak = userdir / ".ssh" / "authorized_keys"
            if ak.exists():
                st = ak.stat()
                if st.st_mode & 0o077:
                    bad.append(Finding(
                        id=self.id + f":{userdir.name}",
                        description=f"{ak} has weak permissions",
                        severity=Severity.WARNING,
                    ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="All authorized_keys files permissions OK")


class AUTH_1006_PasswdConsistency(Check):
    id = "AUTH-1006"
    title = "Check passwd and shadow consistency"
    category = "AUTH"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        shadow = Path("/etc/shadow")
        if not passwd.exists() or not shadow.exists():
            f = Finding(id=self.id + ":missing", description="/etc/passwd or /etc/shadow missing", severity=Severity.WARNING)
            return self.fail([f])
        users = {line.split(":")[0] for line in passwd.read_text(encoding="utf-8").splitlines() if line}
        susers = {line.split(":")[0] for line in shadow.read_text(encoding="utf-8").splitlines() if line}
        if not users.issubset(susers):
            missing = users - susers
            f = Finding(id=self.id + ":incons", description=f"Users missing in shadow: {','.join(missing)}", severity=Severity.HIGH)
            return self.fail([f])
        return self.ok(notes="passwd and shadow consistent")
