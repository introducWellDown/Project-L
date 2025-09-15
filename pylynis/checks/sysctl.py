from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class SYSCTL_9000_IpForward(Check):
    id = "SYSCTL-9000"
    title = "Проверка net.ipv4.ip_forward"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/ip_forward")
        if not path.exists():
            return self.skip(notes="Параметр ip_forward недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать ip_forward")
        if val == "0":
            return self.ok(notes="IP forwarding отключён")
        f = Finding(
            id=self.id + ":on",
            description="Включён IP forwarding",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class SYSCTL_9001_IcmpRedirects(Check):
    id = "SYSCTL-9001"
    title = "Проверка net.ipv4.conf.all.accept_redirects"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/accept_redirects")
        if not path.exists():
            return self.skip(notes="Параметр accept_redirects недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать accept_redirects")
        if val == "0":
            return self.ok(notes="ICMP redirects отключены")
        f = Finding(
            id=self.id + ":on",
            description="Разрешены ICMP redirects",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class SYSCTL_9002_SecureRedirects(Check):
    id = "SYSCTL-9002"
    title = "Проверка net.ipv4.conf.all.secure_redirects"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/secure_redirects")
        if not path.exists():
            return self.skip(notes="Параметр secure_redirects недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать secure_redirects")
        if val == "0":
            return self.ok(notes="Secure redirects отключены")
        f = Finding(
            id=self.id + ":on",
            description="Разрешены secure redirects",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class SYSCTL_9003_AcceptSourceRoute(Check):
    id = "SYSCTL-9003"
    title = "Проверка net.ipv4.conf.all.accept_source_route"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/accept_source_route")
        if not path.exists():
            return self.skip(notes="Параметр accept_source_route недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать accept_source_route")
        if val == "0":
            return self.ok(notes="Source routing отключён")
        f = Finding(
            id=self.id + ":on",
            description="Разрешён source routing",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class SYSCTL_9004_LogMartians(Check):
    id = "SYSCTL-9004"
    title = "Проверка net.ipv4.conf.all.log_martians"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/log_martians")
        if not path.exists():
            return self.skip(notes="Параметр log_martians недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать log_martians")
        if val == "1":
            return self.ok(notes="Логирование martian-пакетов включено")
        f = Finding(
            id=self.id + ":off",
            description="Логирование martian-пакетов отключено",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class SYSCTL_9005_Ipv6Disable(Check):
    id = "SYSCTL-9005"
    title = "Проверка net.ipv6.conf.all.disable_ipv6"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if not path.exists():
            return self.skip(notes="Параметр disable_ipv6 недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать disable_ipv6")
        if val == "1":
            return self.ok(notes="IPv6 отключён")
        return self.ok(notes="IPv6 включён")
