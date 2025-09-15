from __future__ import annotations

import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class NETW_5000_OpenTCPPorts(Check):
    id = "NETW-5000"
    title = "Проверка открытых TCP-портов"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ss", "-tln"], check=False)
        if proc.returncode == 0 and proc.stdout:
            return self.ok(notes=f"Найдено строк в выводе ss: {len(proc.stdout.splitlines())}")
        np = run_cmd(["netstat", "-tln"], check=False)
        if np.returncode == 0 and np.stdout:
            return self.ok(notes=f"Найдено строк в выводе netstat: {len(np.stdout.splitlines())}")
        f = Finding(
            id=self.id + ":no_tool",
            description="Не найдено ни ss, ни netstat для проверки портов",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class NETW_5001_FirewallActive(Check):
    id = "NETW-5001"
    title = "Проверка наличия активного файрвола"
    category = "NETW"

    def run(self, ctx):
        for fw in ["ufw", "firewalld", "iptables"]:
            exe = shutil.which(fw)
            if exe:
                return self.ok(notes=f"Найден инструмент файрвола: {fw}")
        f = Finding(
            id=self.id + ":nofw",
            description="Инструменты файрвола не обнаружены",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class NETW_5002_RoutingTable(Check):
    id = "NETW-5002"
    title = "Проверка таблицы маршрутизации"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ip", "route"], check=False)
        if proc.returncode == 0 and proc.stdout:
            lines = proc.stdout.splitlines()
            return self.ok(notes=f"Количество маршрутов: {len(lines)}")
        return self.skip(notes="Команда ip route недоступна")


class NETW_5003_Ipv6Enabled(Check):
    id = "NETW-5003"
    title = "Проверка включён ли IPv6"
    category = "NETW"

    def run(self, ctx):
        path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if not path.exists():
            return self.skip(notes="Файл sysctl для IPv6 недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать состояние IPv6")
        if val == "0":
            return self.ok(notes="IPv6 включён")
        return self.ok(notes="IPv6 отключён")


class NETW_5004_ListenAllInterfaces(Check):
    id = "NETW-5004"
    title = "Проверка сервисов, слушающих на всех интерфейсах"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ss", "-tln"], check=False)
        if proc.returncode != 0 or not proc.stdout:
            return self.skip(notes="Команда ss недоступна")
        bad: list[Finding] = []
        for line in proc.stdout.splitlines():
            if "*:" in line or "0.0.0.0:" in line:
                bad.append(
                    Finding(
                        id=self.id + ":any",
                        description=f"Сервис слушает на всех интерфейсах: {line}",
                        severity=Severity.SUGGESTION,
                    )
                )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Нет сервисов, привязанных ко всем интерфейсам")


class NETW_5005_BridgeInterfaces(Check):
    id = "NETW-5005"
    title = "Проверка наличия мостовых интерфейсов"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ip", "link"], check=False)
        if proc.returncode != 0 or not proc.stdout:
            return self.skip(notes="Команда ip link недоступна")
        if any("bridge" in line for line in proc.stdout.splitlines()):
            return self.ok(notes="Обнаружены мостовые интерфейсы")
        return self.ok(notes="Мостовые интерфейсы не найдены")


class NETW_5006_PromiscuousMode(Check):
    id = "NETW-5006"
    title = "Проверка интерфейсов в режиме promiscuous"
    category = "NETW"

    def run(self, ctx):
        proc = run_cmd(["ip", "-d", "link"], check=False)
        if proc.returncode != 0 or not proc.stdout:
            return self.skip(notes="Команда ip -d link недоступна")
        bad: list[Finding] = []
        for line in proc.stdout.splitlines():
            if "PROMISC" in line:
                bad.append(
                    Finding(
                        id=self.id + ":promisc",
                        description=f"Интерфейс в режиме promiscuous: {line}",
                        severity=Severity.WARNING,
                    )
                )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Интерфейсов в режиме promiscuous не найдено")
