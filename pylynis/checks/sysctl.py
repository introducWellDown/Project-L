from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class SYSCTL_9000_IpForward(Check):
    id = "SYSCTL-9000"
    title = "Check net.ipv4.ip_forward"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/ip_forward")
        if not path.exists():
            return self.skip(notes="ip_forward not available")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="ip_forward disabled")
        f = Finding(id=self.id + ":on", description="IP forwarding enabled", severity=Severity.SUGGESTION)
        return self.fail([f])


class SYSCTL_9001_IcmpRedirects(Check):
    id = "SYSCTL-9001"
    title = "Check net.ipv4.conf.all.accept_redirects"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/accept_redirects")
        if not path.exists():
            return self.skip(notes="accept_redirects not available")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="ICMP redirects disabled")
        f = Finding(id=self.id + ":on", description="ICMP redirects enabled", severity=Severity.WARNING)
        return self.fail([f])


class SYSCTL_9002_SecureRedirects(Check):
    id = "SYSCTL-9002"
    title = "Check net.ipv4.conf.all.secure_redirects"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/secure_redirects")
        if not path.exists():
            return self.skip(notes="secure_redirects not available")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="Secure redirects disabled")
        f = Finding(id=self.id + ":on", description="Secure redirects enabled", severity=Severity.SUGGESTION)
        return self.fail([f])


class SYSCTL_9003_AcceptSourceRoute(Check):
    id = "SYSCTL-9003"
    title = "Check net.ipv4.conf.all.accept_source_route"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/accept_source_route")
        if not path.exists():
            return self.skip(notes="accept_source_route not available")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="Source routing disabled")
        f = Finding(id=self.id + ":on", description="Source routing enabled", severity=Severity.WARNING)
        return self.fail([f])


class SYSCTL_9004_LogMartians(Check):
    id = "SYSCTL-9004"
    title = "Check net.ipv4.conf.all.log_martians"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/log_martians")
        if not path.exists():
            return self.skip(notes="log_martians not available")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="Log martians enabled")
        f = Finding(id=self.id + ":off", description="Log martians disabled", severity=Severity.SUGGESTION)
        return self.fail([f])


class SYSCTL_9005_Ipv6Disable(Check):
    id = "SYSCTL-9005"
    title = "Check net.ipv6.conf.all.disable_ipv6"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if not path.exists():
            return self.skip(notes="disable_ipv6 not available")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="IPv6 disabled")
        return self.ok(notes="IPv6 enabled")
