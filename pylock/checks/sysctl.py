from __future__ import annotations

from pathlib import Path
import subprocess
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

class SYSCTL_9006_RpFilter(Check):
    id = "SYSCTL-9006"
    title = "Проверка net.ipv4.conf.all.rp_filter"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/rp_filter")
        if not path.exists():
            return self.skip(notes="rp_filter недоступен")
        val = path.read_text().strip()
        if val in {"1", "2"}:
            return self.ok(notes=f"rp_filter включён ({val})")
        return self.fail([
            Finding(
                id=self.id + ":off",
                description="rp_filter выключен — защита от IP spoofing отсутствует",
                severity=Severity.WARNING,
            )
        ])


class SYSCTL_9007_IcmpBroadcast(Check):
    id = "SYSCTL-9007"
    title = "Проверка net.ipv4.icmp_echo_ignore_broadcasts"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
        if not path.exists():
            return self.skip(notes="icmp_echo_ignore_broadcasts недоступен")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="ICMP broadcast игнорируются")
        return self.fail([
            Finding(
                id=self.id + ":on",
                description="ICMP broadcast разрешены (может быть использован Smurf-атакой)",
                severity=Severity.WARNING,
            )
        ])


class NETW_5007_NtpActive(Check):
    id = "NETW-5007"
    title = "Проверка синхронизации времени (ntpd/chronyd/systemd-timesyncd)"
    category = "NETW"

    def run(self, ctx):
        for svc in ("ntpd", "chronyd", "systemd-timesyncd"):
            try:
                proc = subprocess.run(["pidof", svc], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                if proc.returncode == 0:
                    return self.ok(notes=f"Сервис синхронизации времени активен: {svc}")
            except Exception:
                continue
        return self.fail([
            Finding(
                id=self.id + ":inactive",
                description="Службы синхронизации времени не найдены",
                severity=Severity.SUGGESTION,
            )
        ])


class SYSCTL_9008_Ipv6Forward(Check):
    id = "SYSCTL-9008"
    title = "Проверка net.ipv6.conf.all.forwarding"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv6/conf/all/forwarding")
        if not path.exists():
            return self.skip(notes="IPv6 forwarding недоступен")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="IPv6 forwarding отключён")
        return self.fail([
            Finding(
                id=self.id + ":on",
                description="IPv6 forwarding включён",
                severity=Severity.WARNING,
            )
        ])

class SYSCTL_9009_SendRedirects(Check):
    id = "SYSCTL-9009"
    title = "Проверка net.ipv4.conf.all.send_redirects"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/conf/all/send_redirects")
        if not path.exists():
            return self.skip(notes="send_redirects недоступен")
        val = path.read_text().strip()
        if val == "0":
            return self.ok(notes="send_redirects отключены")
        return self.fail([
            Finding(
                id=self.id + ":on",
                description="send_redirects включены — небезопасно",
                severity=Severity.WARNING,
            )
        ])


class SYSCTL_9010_IcmpBogusResponses(Check):
    id = "SYSCTL-9010"
    title = "Проверка net.ipv4.icmp_ignore_bogus_error_responses"
    category = "SYSCTL"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses")
        if not path.exists():
            return self.skip(notes="icmp_ignore_bogus_error_responses недоступен")
        val = path.read_text().strip()
        if val == "1":
            return self.ok(notes="Неверные ICMP-ответы игнорируются")
        return self.fail([
            Finding(
                id=self.id + ":off",
                description="Система принимает bogus ICMP-ответы",
                severity=Severity.SUGGESTION,
            )
        ])
