from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class SSH_8000_SshdConfigExists(Check):
    id = "SSH-8000"
    title = "Check if sshd_config exists"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            return self.ok(notes="sshd_config found")
        return self.fail([Finding(id=self.id + ":missing", description="sshd_config not found", severity=Severity.WARNING)])


class SSH_8001_PermitRootLogin(Check):
    id = "SSH-8001"
    title = "Check PermitRootLogin setting"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="sshd_config not found")
        data = p.read_text(encoding="utf-8", errors="ignore")
        if "PermitRootLogin no" in data:
            return self.ok(notes="Root login disabled")
        return self.fail([Finding(id=self.id + ":rootlogin", description="Root login allowed via SSH", severity=Severity.WARNING)])


class SSH_8002_PasswordAuthentication(Check):
    id = "SSH-8002"
    title = "Check PasswordAuthentication setting"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="sshd_config not found")
        data = p.read_text(encoding="utf-8", errors="ignore")
        if "PasswordAuthentication no" in data:
            return self.ok(notes="PasswordAuthentication disabled")
        return self.fail([Finding(id=self.id + ":pwdauth", description="Password authentication enabled", severity=Severity.SUGGESTION)])


class SSH_8003_ProtocolVersion(Check):
    id = "SSH-8003"
    title = "Check SSH protocol version"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="sshd_config not found")
        data = p.read_text(encoding="utf-8", errors="ignore")
        if "Protocol 2" in data:
            return self.ok(notes="Protocol 2 enforced")
        return self.fail([Finding(id=self.id + ":proto", description="Protocol 2 not enforced", severity=Severity.WARNING)])


class SSH_8004_IdleTimeout(Check):
    id = "SSH-8004"
    title = "Check ClientAliveInterval setting"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="sshd_config not found")
        data = p.read_text(encoding="utf-8", errors="ignore")
        if "ClientAliveInterval" in data:
            return self.ok(notes="ClientAliveInterval set")
        return self.fail([Finding(id=self.id + ":idle", description="No ClientAliveInterval set", severity=Severity.SUGGESTION)])


class SSH_8005_StrictModes(Check):
    id = "SSH-8005"
    title = "Check StrictModes setting"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="sshd_config not found")
        data = p.read_text(encoding="utf-8", errors="ignore")
        if "StrictModes yes" in data:
            return self.ok(notes="StrictModes enabled")
        return self.fail([Finding(id=self.id + ":strict", description="StrictModes not enabled", severity=Severity.SUGGESTION)])


class SSH_8006_X11Forwarding(Check):
    id = "SSH-8006"
    title = "Check X11Forwarding setting"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="sshd_config not found")
        data = p.read_text(encoding="utf-8", errors="ignore")
        if "X11Forwarding no" in data:
            return self.ok(notes="X11 forwarding disabled")
        return self.fail([Finding(id=self.id + ":x11", description="X11 forwarding enabled", severity=Severity.SUGGESTION)])
