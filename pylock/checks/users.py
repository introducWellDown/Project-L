from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class USERS_10000_RootUid(Check):
    id = "USERS-10000"
    title = "Проверка наличия нескольких аккаунтов с UID 0"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="Файл /etc/passwd отсутствует")
        try:
            roots = [
                line for line in passwd.read_text(encoding="utf-8").splitlines()
                if len(line.split(":")) > 2 and line.split(":")[2] == "0"
            ]
        except Exception:
            return self.skip(notes="Не удалось прочитать /etc/passwd")
        if len(roots) > 1:
            f = Finding(
                id=self.id + ":multi",
                description=f"Несколько аккаунтов с UID 0: {len(roots)}",
                severity=Severity.HIGH,
            )
            return self.fail([f])
        return self.ok(notes="UID 0 имеет только root")


class USERS_10001_EmptyPasswords(Check):
    id = "USERS-10001"
    title = "Проверка пользователей с пустыми паролями"
    category = "USERS"

    def run(self, ctx):
        shadow = Path("/etc/shadow")
        if not shadow.exists():
            return self.skip(notes="Файл /etc/shadow отсутствует")
        bad: list[Finding] = []
        try:
            for line in shadow.read_text(encoding="utf-8").splitlines():
                parts = line.split(":")
                if len(parts) > 1 and parts[1] == "":
                    bad.append(
                        Finding(
                            id=self.id + f":{parts[0]}",
                            description=f"У пользователя {parts[0]} пустой пароль",
                            severity=Severity.HIGH,
                        )
                    )
        except Exception:
            return self.skip(notes="Не удалось прочитать /etc/shadow")
        if bad:
            return self.fail(bad)
        return self.ok(notes="Пользователей с пустыми паролями не найдено")


class USERS_10002_HomeDirectories(Check):
    id = "USERS-10002"
    title = "Проверка прав на домашние директории пользователей"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="Файл /etc/passwd отсутствует")
        bad: list[Finding] = []
        try:
            for line in passwd.read_text(encoding="utf-8").splitlines():
                parts = line.split(":")
                if len(parts) > 5:
                    home = Path(parts[5])
                    if home.exists():
                        try:
                            st = home.stat()
                        except (PermissionError, FileNotFoundError):
                            continue
                        if st.st_mode & 0o022:
                            bad.append(
                                Finding(
                                    id=self.id + f":{parts[0]}",
                                    description=f"Домашняя директория {parts[0]} имеет слишком широкие права",
                                    severity=Severity.SUGGESTION,
                                )
                            )
        except Exception:
            return self.skip(notes="Не удалось прочитать /etc/passwd")
        if bad:
            return self.fail(bad)
        return self.ok(notes="Права домашних директорий пользователей корректны")


class USERS_10003_NologinShells(Check):
    id = "USERS-10003"
    title = "Проверка системных аккаунтов на использование nologin"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="Файл /etc/passwd отсутствует")
        bad: list[Finding] = []
        try:
            for line in passwd.read_text(encoding="utf-8").splitlines():
                parts = line.split(":")
                if len(parts) > 6:
                    shell = parts[6]
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    if uid < 1000 and not ("nologin" in shell or "false" in shell):
                        bad.append(
                            Finding(
                                id=self.id + f":{parts[0]}",
                                description=f"Системный аккаунт {parts[0]} использует shell {shell}",
                                severity=Severity.SUGGESTION,
                            )
                        )
        except Exception:
            return self.skip(notes="Не удалось прочитать /etc/passwd")
        if bad:
            return self.fail(bad)
        return self.ok(notes="Все системные аккаунты используют nologin/false")


class USERS_10004_DuplicateUIDs(Check):
    id = "USERS-10004"
    title = "Проверка на дублирующиеся UID"
    category = "USERS"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="Файл /etc/passwd отсутствует")
        uids = {}
        bad: list[Finding] = []
        try:
            for line in passwd.read_text(encoding="utf-8").splitlines():
                parts = line.split(":")
                if len(parts) > 2:
                    uid = parts[2]
                    if uid in uids:
                        bad.append(
                            Finding(
                                id=self.id + f":{parts[0]}",
                                description=f"UID {uid} используется у {parts[0]} и {uids[uid]}",
                                severity=Severity.WARNING,
                            )
                        )
                    else:
                        uids[uid] = parts[0]
        except Exception:
            return self.skip(notes="Не удалось прочитать /etc/passwd")
        if bad:
            return self.fail(bad)
        return self.ok(notes="Дублирующихся UID не найдено")


class USERS_10005_RootPathSanity(Check):
    id = "USERS-10005"
    title = "Проверка PATH root на небезопасные записи"
    category = "USERS"

    def run(self, ctx):
        profile = Path("/root/.profile")
        if not profile.exists():
            return self.skip(notes="Файл /root/.profile отсутствует")
        try:
            lines = profile.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return self.skip(notes="Не удалось прочитать /root/.profile")
        path = None
        for line in lines:
            if line.startswith("PATH="):
                path = line.split("=", 1)[1]
                break
        if not path:
            return self.skip(notes="PATH не найден в /root/.profile")
        bad: list[Finding] = []
        for p in path.split(":"):
            if p == "" or p == ".":
                bad.append(
                    Finding(
                        id=self.id + ":dot",
                        description="PATH root содержит '.' (текущую директорию)",
                        severity=Severity.HIGH,
                    )
                )
        if bad:
            return self.fail(bad)
        return self.ok(notes="PATH root безопасен")
