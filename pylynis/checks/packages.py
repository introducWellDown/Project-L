from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class PKGS_6000_PackageManager(Check):
    id = "PKGS-6000"
    title = "Определение доступного пакетного менеджера"
    category = "PKGS"

    def run(self, ctx):
        candidates = ["apt", "apt-get", "dnf", "yum", "zypper", "pacman", "apk", "brew", "port"]
        found = [c for c in candidates if shutil.which(c)]
        if found:
            return self.ok(notes=f"Доступные пакетные менеджеры: {', '.join(found)}")
        f = Finding(
            id=self.id + ":none",
            description="Не найден ни один известный пакетный менеджер",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class PKGS_6001_AptUpdates(Check):
    id = "PKGS-6001"
    title = "Проверка доступных обновлений apt"
    category = "PKGS"

    def run(self, ctx):
        if not shutil.which("apt"):
            return self.skip(notes="apt недоступен")
        proc = run_cmd(["apt", "list", "--upgradeable"], check=False)
        if proc.returncode == 0 and proc.stdout:
            lines = [l for l in proc.stdout.splitlines() if l and not l.startswith("Listing")]
            if lines:
                f = Finding(
                    id=self.id + ":updates",
                    description=f"Доступно обновлений пакетов через apt: {len(lines)}",
                    severity=Severity.SUGGESTION,
                )
                return self.fail([f])
            return self.ok(notes="Доступных обновлений apt нет")
        return self.skip(notes="Не удалось выполнить apt list")


class PKGS_6002_YumCheckUpdates(Check):
    id = "PKGS-6002"
    title = "Проверка доступных обновлений yum/dnf"
    category = "PKGS"

    def run(self, ctx):
        if shutil.which("dnf"):
            proc = run_cmd(["dnf", "check-update", "-q"], check=False)
        elif shutil.which("yum"):
            proc = run_cmd(["yum", "check-update", "-q"], check=False)
        else:
            return self.skip(notes="yum/dnf недоступен")
        if proc.returncode in (0, 100):
            if proc.returncode == 100:
                f = Finding(
                    id=self.id + ":updates",
                    description="Доступны обновления через yum/dnf",
                    severity=Severity.SUGGESTION,
                )
                return self.fail([f])
            return self.ok(notes="Доступных обновлений yum/dnf нет")
        return self.skip(notes="Не удалось выполнить yum/dnf check-update")


class PKGS_6003_PackageDbConsistency(Check):
    id = "PKGS-6003"
    title = "Проверка целостности базы пакетов"
    category = "PKGS"

    def run(self, ctx):
        if shutil.which("dpkg"):
            proc = run_cmd(["dpkg", "--audit"], check=False)
            if proc.returncode == 0 and not proc.stdout.strip():
                return self.ok(notes="База dpkg в порядке")
            if proc.stdout.strip():
                f = Finding(
                    id=self.id + ":issues",
                    description="dpkg сообщает о проблемах",
                    severity=Severity.WARNING,
                )
                return self.fail([f])
        if shutil.which("rpm"):
            proc = run_cmd(["rpm", "--verify", "-a"], check=False)
            if proc.returncode == 0 and not proc.stdout.strip():
                return self.ok(notes="База rpm в порядке")
            if proc.stdout.strip():
                f = Finding(
                    id=self.id + ":issues",
                    description="rpm сообщает о проблемах",
                    severity=Severity.WARNING,
                )
                return self.fail([f])
        return self.skip(notes="dpkg или rpm не найдены")


class PKGS_6004_SignatureChecking(Check):
    id = "PKGS-6004"
    title = "Проверка проверки подписи пакетов"
    category = "PKGS"

    def run(self, ctx):
        if Path("/etc/apt/apt.conf.d").exists():
            confs = list(Path("/etc/apt/apt.conf.d").glob("*.conf"))
            for c in confs:
                try:
                    data = c.read_text(encoding="utf-8", errors="ignore")
                except (PermissionError, FileNotFoundError):
                    continue
                if "AllowUnauthenticated" in data and "true" in data:
                    f = Finding(
                        id=self.id + ":unauth",
                        description="APT разрешает установку неподписанных пакетов",
                        severity=Severity.HIGH,
                    )
                    return self.fail([f])
            return self.ok(notes="APT проверяет подписи пакетов")
        if Path("/etc/yum.conf").exists():
            try:
                data = Path("/etc/yum.conf").read_text(encoding="utf-8", errors="ignore")
            except (PermissionError, FileNotFoundError):
                return self.skip(notes="Не удалось прочитать /etc/yum.conf")
            if "gpgcheck=0" in data:
                f = Finding(
                    id=self.id + ":gpg",
                    description="В YUM/DNF отключена проверка подписей пакетов",
                    severity=Severity.HIGH,
                )
                return self.fail([f])
            return self.ok(notes="В YUM/DNF включена проверка подписей пакетов")
        return self.skip(notes="Не найден конфиг известного пакетного менеджера")


class PKGS_6005_UnattendedUpgrades(Check):
    id = "PKGS-6005"
    title = "Проверка настройки unattended-upgrades"
    category = "PKGS"

    def run(self, ctx):
        if Path("/etc/apt/apt.conf.d/20auto-upgrades").exists():
            return self.ok(notes="unattended-upgrades настроен")
        return self.skip(notes="unattended-upgrades не настроен")

import shutil

class PKGS_6006_DangerousPackages(Check):
    id = "PKGS-6006"
    title = "Проверка наличия небезопасных пакетов"
    category = "PKGS"

    def run(self, ctx):
        bad_pkgs = ["telnet", "rsh-client", "rsh-server", "tftp", "talk", "ftp"]
        found = []
        if shutil.which("dpkg"):
            for pkg in bad_pkgs:
                proc = subprocess.run(["dpkg", "-s", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if proc.returncode == 0:
                    found.append(pkg)
        elif shutil.which("rpm"):
            for pkg in bad_pkgs:
                proc = subprocess.run(["rpm", "-q", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if proc.returncode == 0:
                    found.append(pkg)
        if found:
            return self.fail([
                Finding(
                    id=self.id + ":present",
                    description=f"Найдено небезопасных пакетов: {', '.join(found)}",
                    severity=Severity.HIGH,
                )
            ])
        return self.ok(notes="Небезопасные пакеты отсутствуют")
