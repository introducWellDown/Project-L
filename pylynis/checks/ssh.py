from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class SSH_8000_SshdConfigExists(Check):
    id = "SSH-8000"
    title = "Проверка наличия sshd_config"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            return self.ok(notes="Файл sshd_config найден")
        return self.fail([
            Finding(
                id=self.id + ":missing",
                description="Файл sshd_config не найден",
                severity=Severity.WARNING,
            )
        ])


class SSH_8001_PermitRootLogin(Check):
    id = "SSH-8001"
    title = "Проверка параметра PermitRootLogin"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="Файл sshd_config отсутствует")
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return self.skip(notes="Не удалось прочитать sshd_config")
        if "PermitRootLogin no" in data:
            return self.ok(notes="Вход root по SSH запрещён")
        return self.fail([
            Finding(
                id=self.id + ":rootlogin",
                description="Разрешён вход root по SSH",
                severity=Severity.WARNING,
            )
        ])


class SSH_8002_PasswordAuthentication(Check):
    id = "SSH-8002"
    title = "Проверка параметра PasswordAuthentication"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="Файл sshd_config отсутствует")
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return self.skip(notes="Не удалось прочитать sshd_config")
        if "PasswordAuthentication no" in data:
            return self.ok(notes="Аутентификация по паролю отключена")
        return self.fail([
            Finding(
                id=self.id + ":pwdauth",
                description="Разрешена аутентификация по паролю",
                severity=Severity.SUGGESTION,
            )
        ])


class SSH_8003_ProtocolVersion(Check):
    id = "SSH-8003"
    title = "Проверка версии протокола SSH"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="Файл sshd_config отсутствует")
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return self.skip(notes="Не удалось прочитать sshd_config")
        if "Protocol 2" in data:
            return self.ok(notes="Используется только протокол SSH 2")
        return self.fail([
            Finding(
                id=self.id + ":proto",
                description="Не принудительно используется SSH Protocol 2",
                severity=Severity.WARNING,
            )
        ])


class SSH_8004_IdleTimeout(Check):
    id = "SSH-8004"
    title = "Проверка параметра ClientAliveInterval"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="Файл sshd_config отсутствует")
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return self.skip(notes="Не удалось прочитать sshd_config")
        if "ClientAliveInterval" in data:
            return self.ok(notes="Задан ClientAliveInterval")
        return self.fail([
            Finding(
                id=self.id + ":idle",
                description="Параметр ClientAliveInterval не задан",
                severity=Severity.SUGGESTION,
            )
        ])


class SSH_8005_StrictModes(Check):
    id = "SSH-8005"
    title = "Проверка параметра StrictModes"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="Файл sshd_config отсутствует")
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return self.skip(notes="Не удалось прочитать sshd_config")
        if "StrictModes yes" in data:
            return self.ok(notes="StrictModes включён")
        return self.fail([
            Finding(
                id=self.id + ":strict",
                description="StrictModes не включён",
                severity=Severity.SUGGESTION,
            )
        ])


class SSH_8006_X11Forwarding(Check):
    id = "SSH-8006"
    title = "Проверка параметра X11Forwarding"
    category = "SSH"

    def run(self, ctx):
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return self.skip(notes="Файл sshd_config отсутствует")
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return self.skip(notes="Не удалось прочитать sshd_config")
        if "X11Forwarding no" in data:
            return self.ok(notes="X11 Forwarding отключён")
        return self.fail([
            Finding(
                id=self.id + ":x11",
                description="X11 Forwarding включён",
                severity=Severity.SUGGESTION,
            )
        ])
