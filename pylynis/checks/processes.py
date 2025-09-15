from __future__ import annotations

import os
import subprocess

from .base import Check
from ..core.types import Finding, Severity


class PROC_7000_RootProcesses(Check):
    id = "PROC-7000"
    title = "Check processes running as root"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "user,comm"], text=True)
        except Exception:
            return self.skip(notes="ps not available")
        root_procs = [line for line in output.splitlines() if line.startswith("root ")]
        return self.ok(notes=f"Root processes: {len(root_procs)}")


class PROC_7001_ZombieProcesses(Check):
    id = "PROC-7001"
    title = "Check for zombie processes"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "stat,comm"], text=True)
        except Exception:
            return self.skip(notes="ps not available")
        zombies = [line for line in output.splitlines() if line.startswith("Z")]  # STAT Z
        if zombies:
            f = Finding(id=self.id + ":zombies", description=f"Found {len(zombies)} zombie processes", severity=Severity.WARNING)
            return self.fail([f])
        return self.ok(notes="No zombie processes")


class PROC_7002_SuspiciousTmpExec(Check):
    id = "PROC-7002"
    title = "Check for processes executing from /tmp"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "pid,comm,args"], text=True)
        except Exception:
            return self.skip(notes="ps not available")
        bad: list[Finding] = []
        for line in output.splitlines():
            if "/tmp/" in line:
                bad.append(Finding(id=self.id + ":tmp", description=f"Process executed from /tmp: {line}", severity=Severity.HIGH))
        if bad:
            return self.fail(bad)
        return self.ok(notes="No processes executed from /tmp")


class PROC_7003_OrphanedProcesses(Check):
    id = "PROC-7003"
    title = "Check for orphaned processes (ppid=1)"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "ppid,comm"], text=True)
        except Exception:
            return self.skip(notes="ps not available")
        orphans = [line for line in output.splitlines() if line.strip().startswith("1 ")]
        if orphans:
            return self.ok(notes=f"Orphaned processes: {len(orphans)}")
        return self.ok(notes="No orphaned processes")


class PROC_7004_LongRunningHighCpu(Check):
    id = "PROC-7004"
    title = "Check for processes with high CPU usage"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "%cpu,comm"], text=True)
        except Exception:
            return self.skip(notes="ps not available")
        bad: list[Finding] = []
        for line in output.splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    cpu = float(parts[0])
                    if cpu > 80.0:
                        bad.append(Finding(id=self.id + ":cpu", description=f"High CPU: {line}", severity=Severity.SUGGESTION))
                except ValueError:
                    continue
        if bad:
            return self.fail(bad)
        return self.ok(notes="No high CPU processes detected")


class PROC_7005_UnknownUsers(Check):
    id = "PROC-7005"
    title = "Check for processes running as unknown users"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "user,comm"], text=True)
        except Exception:
            return self.skip(notes="ps not available")
        known_users = {u.strip().split(":")[0] for u in open("/etc/passwd", encoding="utf-8").read().splitlines()}
        bad: list[Finding] = []
        for line in output.splitlines()[1:]:
            user = line.split(None, 1)[0]
            if user not in known_users:
                bad.append(Finding(id=self.id + ":unkusr", description=f"Process with unknown user {user}", severity=Severity.WARNING))
        if bad:
            return self.fail(bad)
        return self.ok(notes="All process users valid")
