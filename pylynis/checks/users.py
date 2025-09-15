from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class USERS_10000_RootUid(Check):
    id = "USERS-10000"
    title = "Check for multiple UID 0 accounts"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="/etc/passwd not found")
        roots = [line for line in passwd.read_text(encoding="utf-8").splitlines() if line.split(":")[2] == "0"]
        if len(roots) > 1:
            f = Finding(id=self.id + ":multi", description=f"Multiple UID 0 accounts: {len(roots)}", severity=Severity.HIGH)
            return self.fail([f])
        return self.ok(notes="Only root has UID 0")


class USERS_10001_EmptyPasswords(Check):
    id = "USERS-10001"
    title = "Check for users with empty passwords"
    category = "USERS"

    def run(self, ctx):
        shadow = Path("/etc/shadow")
        if not shadow.exists():
            return self.skip(notes="/etc/shadow not found")
        bad: list[Finding] = []
        for line in shadow.read_text(encoding="utf-8").splitlines():
            parts = line.split(":")
            if len(parts) > 1 and parts[1] == "":
                bad.append(Finding(id=self.id + f":{parts[0]}", description=f"User {parts[0]} has empty password", severity=Severity.HIGH))
        if bad:
            return self.fail(bad)
        return self.ok(notes="No empty passwords found")


class USERS_10002_HomeDirectories(Check):
    id = "USERS-10002"
    title = "Check user home directory permissions"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="/etc/passwd not found")
        bad: list[Finding] = []
        for line in passwd.read_text(encoding="utf-8").splitlines():
            parts = line.split(":")
            if len(parts) > 5:
                home = Path(parts[5])
                if home.exists():
                    st = home.stat()
                    if st.st_mode & 0o022:
                        bad.append(Finding(id=self.id + f":{parts[0]}", description=f"Home dir of {parts[0]} has weak perms", severity=Severity.SUGGESTION))
        if bad:
            return self.fail(bad)
        return self.ok(notes="All home directories permissions look good")


class USERS_10003_NologinShells(Check):
    id = "USERS-10003"
    title = "Check system accounts with nologin shells"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="/etc/passwd not found")
        bad: list[Finding] = []
        for line in passwd.read_text(encoding="utf-8").splitlines():
            parts = line.split(":")
            if len(parts) > 6:
                shell = parts[6]
                uid = int(parts[2])
                if uid < 1000 and not ("nologin" in shell or "false" in shell):
                    bad.append(Finding(id=self.id + f":{parts[0]}", description=f"System account {parts[0]} has shell {shell}", severity=Severity.SUGGESTION))
        if bad:
            return self.fail(bad)
        return self.ok(notes="System accounts use nologin/false shells")


class USERS_10004_DuplicateUIDs(Check):
    id = "USERS-10004"
    title = "Check for duplicate UIDs"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="/etc/passwd not found")
        uids = {}
        bad: list[Finding] = []
        for line in passwd.read_text(encoding="utf-8").splitlines():
            parts = line.split(":")
            if len(parts) > 2:
                uid = parts[2]
                if uid in uids:
                    bad.append(Finding(id=self.id + f":{parts[0]}", description=f"UID {uid} duplicated: {parts[0]} and {uids[uid]}", severity=Severity.WARNING))
                else:
                    uids[uid] = parts[0]
        if bad:
            return self.fail(bad)
        return self.ok(notes="No duplicate UIDs found")


class USERS_10005_RootPathSanity(Check):
    id = "USERS-10005"
    title = "Check root PATH for insecure entries"
    category = "USERS"

    def run(self, ctx):
        path = None
        for line in Path("/root/.profile").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("PATH="):
                path = line.split("=", 1)[1]
                break
        if not path:
            return self.skip(notes="No PATH in /root/.profile")
        bad: list[Finding] = []
        for p in path.split(":"):
            if p == "" or p == ".":
                bad.append(Finding(id=self.id + ":dot", description="Root PATH includes '.'", severity=Severity.HIGH))
        if bad:
            return self.fail(bad)
        return self.ok(notes="Root PATH looks safe")
