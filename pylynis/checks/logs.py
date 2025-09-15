from __future__ import annotations

import subprocess
import os
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity

class LOGS_1000_AuditdActive(Check):
    id = "LOGS-1000"
    title = "Проверка активности auditd"
    category = "LOGS"

    def run(self, ctx):
        if Path("/sbin/auditd").exists() or Path("/usr/sbin/auditd").exists():
            try:
                proc = subprocess.run(["pidof", "auditd"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                if proc.returncode == 0:
                    return self.ok(notes="auditd работает")
                return self.fail([
                    Finding(
                        id=self.id + ":inactive",
                        description="auditd установлен, но не запущен",
                        severity=Severity.WARNING,
                    )
                ])
            except Exception:
                return self.skip(notes="Не удалось проверить состояние auditd")
        return self.skip(notes="auditd не установлен")

class LOGS_1001_WtmpBtmp(Check):
    id = "LOGS-1001"
    title = "Проверка наличия файлов учёта входов/выходов (wtmp, btmp)"
    category = "LOGS"

    def run(self, ctx):
        files = [Path("/var/log/wtmp"), Path("/var/log/btmp")]
        bad: list[Finding] = []
        for f in files:
            if not f.exists():
                bad.append(Finding(
                    id=self.id + f":missing",
                    description=f"Файл {f} отсутствует",
                    severity=Severity.WARNING,
                ))
            else:
                st = f.stat()
                if st.st_mode & 0o022:
                    bad.append(Finding(
                        id=self.id + f":perms",
                        description=f"Файл {f} имеет небезопасные права",
                        severity=Severity.HIGH,
                    ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="Файлы wtmp/btmp присутствуют и защищены")


class LOGS_1002_LogrotateConf(Check):
    id = "LOGS-1002"
    title = "Проверка наличия конфигурации logrotate"
    category = "LOGS"

    def run(self, ctx):
        if Path("/etc/logrotate.conf").exists():
            return self.ok(notes="logrotate настроен")
        return self.skip(notes="logrotate.conf не найден")

class LOGS_1003_JournaldPersistent(Check):
    id = "LOGS-1003"
    title = "Проверка persistent-хранения journald"
    category = "LOGS"

    def run(self, ctx):
        path = Path("/etc/systemd/journald.conf")
        if not path.exists():
            return self.skip(notes="journald.conf не найден")
        data = path.read_text(encoding="utf-8", errors="ignore")
        for line in data.splitlines():
            if line.strip().startswith("Storage="):
                if "persistent" in line:
                    return self.ok(notes="journald хранит логи persistent")
                return self.fail([
                    Finding(
                        id=self.id + ":volatile",
                        description="journald хранит логи только в памяти",
                        severity=Severity.WARNING,
                    )
                ])
        return self.skip(notes="Параметр Storage не задан в journald.conf")
