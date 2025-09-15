from __future__ import annotations

import os
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class FILE_3000_EtcHostsPermissions(Check):
    id = "FILE-3000"
    title = "Check /etc/hosts permissions"
    category = "FILE"

    def run(self, ctx):
        fpath = Path("/etc/hosts")
        if not fpath.exists():
            return self.skip(notes="/etc/hosts missing")
        st = fpath.stat()
        if st.st_mode & 0o022:
            f = Finding(id=self.id + ":perm", description="/etc/hosts is group/world-writable", severity=Severity.WARNING)
            return self.fail([f])
        return self.ok(notes="/etc/hosts permissions OK")


class FILE_3001_TmpPermissions(Check):
    id = "FILE-3001"
    title = "Check /tmp sticky bit"
    category = "FILE"

    def run(self, ctx):
        tmp = Path("/tmp")
        if not tmp.exists():
            return self.skip(notes="/tmp not present")
        if tmp.stat().st_mode & 0o1000:
            return self.ok(notes="/tmp has sticky bit set")
        f = Finding(id=self.id + ":sticky", description="/tmp missing sticky bit", severity=Severity.WARNING)
        return self.fail([f])


class FILE_3002_WorldWritableDirs(Check):
    id = "FILE-3002"
    title = "Find world-writable directories without sticky bit"
    category = "FILE"

    def run(self, ctx):
        bad: list[Finding] = []
        for root, dirs, files in os.walk("/", topdown=True):
            try:
                for d in dirs:
                    path = Path(root) / d
                    st = path.lstat()
                    if st.st_mode & 0o002 and not (st.st_mode & 0o1000):
                        bad.append(Finding(
                            id=self.id + f":{path}",
                            description=f"World-writable dir without sticky bit: {path}",
                            severity=Severity.WARNING,
                        ))
            except PermissionError:
                continue
        if bad:
            return self.fail(bad)
        return self.ok(notes="No unsafe world-writable dirs found")


class FILE_3003_SuidBinaries(Check):
    id = "FILE-3003"
    title = "List SUID binaries"
    category = "FILE"

    def run(self, ctx):
        found = []
        for root, dirs, files in os.walk("/", topdown=True):
            try:
                for f in files:
                    path = Path(root) / f
                    st = path.lstat()
                    if st.st_mode & 0o4000:
                        found.append(str(path))
            except PermissionError:
                continue
        if found:
            return self.ok(notes=f"Found {len(found)} SUID binaries")
        return self.ok(notes="No SUID binaries detected")


class FILE_3004_CoreDumps(Check):
    id = "FILE-3004"
    title = "Check if core dumps are restricted"
    category = "FILE"

    def run(self, ctx):
        try:
            with open("/proc/sys/kernel/core_pattern", "r", encoding="utf-8") as fh:
                data = fh.read().strip()
        except FileNotFoundError:
            return self.skip(notes="core_pattern not available")
        if data == "|/usr/share/apport/apport %p %s %c %P":
            return self.ok(notes="core dumps handled by apport")
        if data.startswith("|"):
            return self.ok(notes="core dumps piped to handler")
        f = Finding(id=self.id + ":enabled", description="Core dumps may be enabled", severity=Severity.SUGGESTION)
        return self.fail([f])


class FILE_3005_FstabOptions(Check):
    id = "FILE-3005"
    title = "Check /etc/fstab for nodev/nosuid/noexec"
    category = "FILE"

    def run(self, ctx):
        fstab = Path("/etc/fstab")
        if not fstab.exists():
            return self.skip(notes="/etc/fstab not found")
        bad: list[Finding] = []
        for line in fstab.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            fields = line.split()
            if len(fields) >= 4:
                mnt, opts = fields[1], fields[3]
                if mnt in ("/home", "/tmp", "/var"):  # critical mounts
                    for needed in ("nodev", "nosuid", "noexec"):
                        if needed not in opts:
                            bad.append(Finding(
                                id=self.id + f":{mnt}:{needed}",
                                description=f"{mnt} missing {needed} in fstab",
                                severity=Severity.SUGGESTION,
                            ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="fstab mount options look good")


class FILE_3006_EtcSecurityLimits(Check):
    id = "FILE-3006"
    title = "Check /etc/security/limits.conf existence"
    category = "FILE"

    def run(self, ctx):
        p = Path("/etc/security/limits.conf")
        if p.exists():
            return self.ok(notes="limits.conf exists")
        return self.skip(notes="limits.conf not found")
