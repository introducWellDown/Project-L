from __future__ import annotations

import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class NETW_5000_OpenTCPPorts(Check):
    id = "NETW-5000"
    title = "Enumerate listening TCP ports"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ss", "-tln"], check=False)
        if proc.returncode == 0 and proc.stdout:
            return self.ok(notes=f"ss output lines: {len(proc.stdout.splitlines())}")
        np = run_cmd(["netstat", "-tln"], check=False)
        if np.returncode == 0 and np.stdout:
            return self.ok(notes=f"netstat output lines: {len(np.stdout.splitlines())}")
        f = Finding(id=self.id + ":no_tool", description="Neither ss nor netstat available", severity=Severity.WARNING)
        return self.fail([f])


class NETW_5001_FirewallActive(Check):
    id = "NETW-5001"
    title = "Check if firewall is active"
    category = "NETW"

    def run(self, ctx):
        for fw in ["ufw", "firewalld", "iptables"]:
            exe = shutil.which(fw)
            if exe:
                return self.ok(notes=f"Firewall tool found: {fw}")
        f = Finding(id=self.id + ":nofw", description="No firewall tools detected", severity=Severity.SUGGESTION)
        return self.fail([f])


class NETW_5002_RoutingTable(Check):
    id = "NETW-5002"
    title = "Check routing table entries"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ip", "route"], check=False)
        if proc.returncode == 0 and proc.stdout:
            lines = proc.stdout.splitlines()
            return self.ok(notes=f"Routing entries: {len(lines)}")
        return self.skip(notes="ip route not available")


class NETW_5003_Ipv6Enabled(Check):
    id = "NETW-5003"
    title = "Check if IPv6 is enabled"
    category = "NETW"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if not path.exists():
            return self.skip(notes="No IPv6 sysctl")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="IPv6 enabled")
        return self.ok(notes="IPv6 disabled")


class NETW_5004_ListenAllInterfaces(Check):
    id = "NETW-5004"
    title = "Check for services listening on all interfaces"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ss", "-tln"], check=False)
        if proc.returncode != 0:
            return self.skip(notes="ss not available")
        bad: list[Finding] = []
        for line in proc.stdout.splitlines():
            if "*:" in line or "0.0.0.0:" in line:
                bad.append(Finding(id=self.id + ":any", description=f"Service listens on all interfaces: {line}", severity=Severity.SUGGESTION))
        if bad:
            return self.fail(bad)
        return self.ok(notes="No services bound to all interfaces")


class NETW_5005_BridgeInterfaces(Check):
    id = "NETW-5005"
    title = "Check for bridge interfaces"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ip", "link"], check=False)
        if proc.returncode != 0:
            return self.skip(notes="ip link not available")
        if any("bridge" in line for line in proc.stdout.splitlines()):
            return self.ok(notes="Bridge interfaces found")
        return self.ok(notes="No bridge interfaces")


class NETW_5006_PromiscuousMode(Check):
    id = "NETW-5006"
    title = "Check for interfaces in promiscuous mode"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ip", "-d", "link"], check=False)
        if proc.returncode != 0:
            return self.skip(notes="ip link -d not available")
        bad: list[Finding] = []
        for line in proc.stdout.splitlines():
            if "PROMISC" in line:
                bad.append(Finding(id=self.id + ":promisc", description=f"Interface in promiscuous mode: {line}", severity=Severity.WARNING))
        if bad:
            return self.fail(bad)
        return self.ok(notes="No promiscuous interfaces")
