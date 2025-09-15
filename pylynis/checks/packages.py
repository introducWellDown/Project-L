from __future__ import annotations

import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class PKGS_6000_PackageManager(Check):
    id = "PKGS-6000"
    title = "Detect package manager"
    category = "PKGS"

    def run(self, ctx):
        candidates = ["apt", "apt-get", "dnf", "yum", "zypper", "pacman", "apk", "brew", "port"]
        found = [c for c in candidates if shutil.which(c)]
        if found:
            return self.ok(notes=f"Available PMs: {', '.join(found)}")
        f = Finding(id=self.id + ":none", description="No known package manager found", severity=Severity.WARNING)
        return self.fail([f])


class PKGS_6001_AptUpdates(Check):
    id = "PKGS-6001"
    title = "Check for available apt updates"
    category = "PKGS"

    def run(self, ctx):
        if not shutil.which("apt"):  # Debian/Ubuntu
            return self.skip(notes="apt not present")
        proc = run_cmd(["apt", "list", "--upgradeable"], check=False)
        if proc.returncode == 0 and "Listing..." in proc.stdout:
            lines = [l for l in proc.stdout.splitlines() if l and not l.startswith("Listing")]
            if lines:
                f = Finding(id=self.id + ":updates", description=f"Upgradeable packages: {len(lines)}", severity=Severity.SUGGESTION)
                return self.fail([f])
            return self.ok(notes="No apt updates available")
        return self.skip(notes="apt list failed")


class PKGS_6002_YumCheckUpdates(Check):
    id = "PKGS-6002"
    title = "Check for available yum/dnf updates"
    category = "PKGS"

    def run(self, ctx):
        if shutil.which("dnf"):
            proc = run_cmd(["dnf", "check-update", "-q"], check=False)
        elif shutil.which("yum"):
            proc = run_cmd(["yum", "check-update", "-q"], check=False)
        else:
            return self.skip(notes="yum/dnf not present")
        if proc.returncode in (0, 100):
            if proc.returncode == 100:
                f = Finding(id=self.id + ":updates", description="Updates available via yum/dnf", severity=Severity.SUGGESTION)
                return self.fail([f])
            return self.ok(notes="No yum/dnf updates available")
        return self.skip(notes="yum/dnf check-update failed")


class PKGS_6003_PackageDbConsistency(Check):
    id = "PKGS-6003"
    title = "Check package database consistency"
    category = "PKGS"

    def run(self, ctx):
        if shutil.which("dpkg"):
            proc = run_cmd(["dpkg", "--audit"], check=False)
            if proc.returncode == 0 and not proc.stdout.strip():
                return self.ok(notes="dpkg database consistent")
            if proc.stdout.strip():
                f = Finding(id=self.id + ":issues", description="dpkg reports issues", severity=Severity.WARNING)
                return self.fail([f])
        if shutil.which("rpm"):
            proc = run_cmd(["rpm", "--verify", "-a"], check=False)
            if proc.returncode == 0 and not proc.stdout.strip():
                return self.ok(notes="rpm database consistent")
            if proc.stdout.strip():
                f = Finding(id=self.id + ":issues", description="rpm reports issues", severity=Severity.WARNING)
                return self.fail([f])
        return self.skip(notes="No dpkg or rpm found")


class PKGS_6004_SignatureChecking(Check):
    id = "PKGS-6004"
    title = "Check if package signature checking is enabled"
    category = "PKGS"

    def run(self, ctx):
        if Path("/etc/apt/apt.conf.d").exists():
            confs = list(Path("/etc/apt/apt.conf.d").glob("*.conf"))
            for c in confs:
                data = c.read_text(encoding="utf-8", errors="ignore")
                if "AllowUnauthenticated" in data and "true" in data:
                    f = Finding(id=self.id + ":unauth", description="APT allows unauthenticated packages", severity=Severity.HIGH)
                    return self.fail([f])
            return self.ok(notes="APT signature checking enforced")
        if Path("/etc/yum.conf").exists():
            data = Path("/etc/yum.conf").read_text(encoding="utf-8", errors="ignore")
            if "gpgcheck=0" in data:
                f = Finding(id=self.id + ":gpg", description="YUM/DNF signature checking disabled", severity=Severity.HIGH)
                return self.fail([f])
            return self.ok(notes="YUM/DNF signature checking enabled")
        return self.skip(notes="No known package manager config found")


class PKGS_6005_UnattendedUpgrades(Check):
    id = "PKGS-6005"
    title = "Check for unattended-upgrades configuration"
    category = "PKGS"

    def run(self, ctx):
        if Path("/etc/apt/apt.conf.d/20auto-upgrades").exists():
            return self.ok(notes="Unattended-upgrades configured")
        return self.skip(notes="No unattended-upgrades configuration")
