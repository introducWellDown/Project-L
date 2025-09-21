from __future__ import annotations

import subprocess
import os
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity

class SERVICES_1000_X11TcpDisabled(Check):
    id = "SERVICES-1000"
    title = "Проверка отключения TCP для X11"
    category = "SERVICES"

    def run(self, ctx):
        if not Path("/etc/X11").exists():
            return self.skip(notes="X11 не установлен")
        try:
            with open("/etc/X11/xinit/xserverrc", encoding="utf-8", errors="ignore") as fh:
                data = fh.read()
        except FileNotFoundError:
            return self.skip(notes="Конфигурация X11 не найдена")
        if "-nolisten tcp" in data:
            return self.ok(notes="X11 не слушает TCP")
        return self.fail([
            Finding(
                id=self.id + ":tcp",
                description="X11 слушает TCP-порт — небезопасно",
                severity=Severity.WARNING,
            )
        ])

class SERVICES_1001_CronAccess(Check):
    id = "SERVICES-1001"
    title = "Проверка доступа к cron"
    category = "SERVICES"

    def run(self, ctx):
        cron_allow = Path("/etc/cron.allow")
        cron_deny = Path("/etc/cron.deny")
        if cron_allow.exists():
            return self.ok(notes="cron доступен только пользователям из cron.allow")
        if cron_deny.exists():
            return self.ok(notes="cron ограничен через cron.deny")
        return self.fail([
            Finding(
                id=self.id + ":unrestricted",
                description="Доступ к cron не ограничен (нет cron.allow/cron.deny)",
                severity=Severity.SUGGESTION,
            )
        ])


class SERVICES_1002_AtAccess(Check):
    id = "SERVICES-1002"
    title = "Проверка доступа к at"
    category = "SERVICES"

    def run(self, ctx):
        at_allow = Path("/etc/at.allow")
        at_deny = Path("/etc/at.deny")
        if at_allow.exists():
            return self.ok(notes="at доступен только пользователям из at.allow")
        if at_deny.exists():
            return self.ok(notes="at ограничен через at.deny")
        return self.fail([
            Finding(
                id=self.id + ":unrestricted",
                description="Доступ к at не ограничен (нет at.allow/at.deny)",
                severity=Severity.SUGGESTION,
            )
        ])

class SERVICES_1003_CupsDisabled(Check):
    id = "SERVICES-1003"
    title = "Проверка службы печати CUPS"
    category = "SERVICES"

    def run(self, ctx):
        try:
            proc = subprocess.run(["pidof", "cupsd"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if proc.returncode == 0:
                return self.fail([
                    Finding(
                        id=self.id + ":active",
                        description="Служба печати cups активна",
                        severity=Severity.SUGGESTION,
                    )
                ])
        except Exception:
            return self.skip(notes="Не удалось проверить cups")
        return self.ok(notes="CUPS не работает")


class SERVICES_1004_NfsDisabled(Check):
    id = "SERVICES-1004"
    title = "Проверка службы NFS"
    category = "SERVICES"

    def run(self, ctx):
        try:
            proc = subprocess.run(["pidof", "nfsd"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if proc.returncode == 0:
                return self.fail([
                    Finding(
                        id=self.id + ":active",
                        description="Служба NFS активна",
                        severity=Severity.SUGGESTION,
                    )
                ])
        except Exception:
            return self.skip(notes="Не удалось проверить nfsd")
        return self.ok(notes="NFS не работает")
