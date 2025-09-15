from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class AUTH_1000_SudoVersion(Check):
    id = "AUTH-1000"
    title = "Проверка наличия и версии sudo"
    category = "AUTH"

    def run(self, ctx):
        exe = shutil.which("sudo")
        if not exe:
            f = Finding(
                id=self.id + ":missing",
                description="Команда sudo не найдена",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        try:
            proc = run_cmd([exe, "--version"], check=False)
            if proc.returncode == 0 and proc.stdout:
                return self.ok(notes=f"Версия sudo: {proc.stdout.splitlines()[0]}")
            f = Finding(
                id=self.id + ":err",
                description="Не удалось запустить sudo",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        except Exception as e:
            f = Finding(
                id=self.id + ":exc",
                description=f"Ошибка при проверке sudo: {e}",
                severity=Severity.WARNING,
            )
            return self.fail([f])


class AUTH_1001_SuBinary(Check):
    id = "AUTH-1001"
    title = "Проверка наличия команды su"
    category = "AUTH"

    def run(self, ctx):
        exe = shutil.which("su")
        if exe:
            return self.ok(notes=f"Команда su найдена: {exe}")
        f = Finding(
            id=self.id + ":missing",
            description="Команда su не найдена",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class AUTH_1002_ShadowPermissions(Check):
    id = "AUTH-1002"
    title = "Проверка прав доступа к /etc/shadow"
    category = "AUTH"

    def run(self, ctx):
        shadow = Path("/etc/shadow")
        if not shadow.exists():
            f = Finding(
                id=self.id + ":missing",
                description="/etc/shadow отсутствует",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        try:
            st = shadow.stat()
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="/etc/shadow недоступен для проверки")
        if st.st_mode & 0o077:
            f = Finding(
                id=self.id + ":perm",
                description="/etc/shadow имеет слишком широкие права доступа",
                severity=Severity.HIGH,
            )
            return self.fail([f])
        return self.ok(notes="Права доступа к /etc/shadow корректны")


class AUTH_1003_PasswdPermissions(Check):
    id = "AUTH-1003"
    title = "Проверка прав доступа к /etc/passwd"
    category = "AUTH"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            f = Finding(
                id=self.id + ":missing",
                description="/etc/passwd отсутствует",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        try:
            st = passwd.stat()
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="/etc/passwd недоступен для проверки")
        if st.st_mode & 0o022:
            f = Finding(
                id=self.id + ":perm",
                description="/etc/passwd доступен для записи другими пользователями",
                severity=Severity.HIGH,
            )
            return self.fail([f])
        return self.ok(notes="Права доступа к /etc/passwd корректны")


class AUTH_1004_PamDDirectory(Check):
    id = "AUTH-1004"
    title = "Проверка наличия каталога /etc/pam.d"
    category = "AUTH"

    def run(self, ctx):
        pamd = Path("/etc/pam.d")
        if pamd.exists() and pamd.is_dir():
            return self.ok(notes="Каталог /etc/pam.d найден")
        f = Finding(
            id=self.id + ":missing",
            description="Каталог /etc/pam.d отсутствует",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class AUTH_1005_SshKeysPermissions(Check):
    id = "AUTH-1005"
    title = "Проверка прав доступа к файлам SSH authorized_keys"
    category = "AUTH"

    def run(self, ctx):
        home = Path("/home")
        bad: list[Finding] = []
        if not home.exists():
            return self.skip(notes="Каталог /home отсутствует")
        for userdir in home.iterdir():
            ak = userdir / ".ssh" / "authorized_keys"
            if ak.exists():
                try:
                    st = ak.stat()
                except (PermissionError, FileNotFoundError):
                    continue
                if st.st_mode & 0o077:
                    bad.append(
                        Finding(
                            id=self.id + f":{userdir.name}",
                            description=f"Файл {ak} имеет слишком широкие права доступа",
                            severity=Severity.WARNING,
                        )
                    )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Все authorized_keys имеют корректные права доступа")


class AUTH_1006_PasswdConsistency(Check):
    id = "AUTH-1006"
    title = "Проверка согласованности /etc/passwd и /etc/shadow"
    category = "AUTH"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        shadow = Path("/etc/shadow")
        if not passwd.exists() or not shadow.exists():
            f = Finding(
                id=self.id + ":missing",
                description="Файлы /etc/passwd или /etc/shadow отсутствуют",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        try:
            users = {
                line.split(":")[0]
                for line in passwd.read_text(encoding="utf-8").splitlines()
                if line and ":" in line
            }
            susers = {
                line.split(":")[0]
                for line in shadow.read_text(encoding="utf-8").splitlines()
                if line and ":" in line
            }
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="Не удалось прочитать passwd или shadow")
        if not users.issubset(susers):
            missing = users - susers
            f = Finding(
                id=self.id + ":incons",
                description=f"Пользователи отсутствуют в shadow: {', '.join(missing)}",
                severity=Severity.HIGH,
            )
            return self.fail([f])
        return self.ok(notes="/etc/passwd и /etc/shadow согласованы")


class AUTH_1007_PasswordAging(Check):
    id = "AUTH-1007"
    title = "Проверка политики устаревания паролей"
    category = "AUTH"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["chage", "-l", "root"], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            return self.skip(notes="Команда chage недоступна")
        if "password must be changed" in output.lower():
            return self.ok(notes="Для root установлен срок действия пароля")
        return self.fail([
            Finding(
                id=self.id + ":noaging",
                description="У root нет политики устаревания пароля",
                severity=Severity.SUGGESTION,
            )
        ])
    
class AUTH_1008_SecureTTY(Check):
    id = "AUTH-1008"
    title = "Проверка наличия /etc/securetty"
    category = "AUTH"

    def run(self, ctx):
        path = Path("/etc/securetty")
        if not path.exists():
            return self.fail([
                Finding(
                    id=self.id + ":missing",
                    description="Файл /etc/securetty отсутствует — root может войти откуда угодно",
                    severity=Severity.WARNING,
                )
            ])
        return self.ok(notes="/etc/securetty присутствует")


class AUTH_1009_GuestAccounts(Check):
    id = "AUTH-1009"
    title = "Проверка наличия гостевых учётных записей"
    category = "AUTH"

    def run(self, ctx):
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            return self.skip(notes="Файл /etc/passwd отсутствует")
        bad: list[Finding] = []
        for line in passwd.read_text(encoding="utf-8").splitlines():
            user = line.split(":")[0]
            if user.lower() in {"guest", "demo", "test"}:
                bad.append(Finding(
                    id=self.id + f":{user}",
                    description=f"Обнаружена небезопасная учётка {user}",
                    severity=Severity.HIGH,
                ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="Гостевых учёток нет")
    

class AUTH_1010_DefaultUmask(Check):
    id = "AUTH-1010"
    title = "Проверка значения umask по умолчанию"
    category = "AUTH"

    def run(self, ctx):
        paths = [Path("/etc/login.defs"), Path("/etc/profile")]
        found_val = None
        for p in paths:
            if p.exists():
                data = p.read_text(encoding="utf-8", errors="ignore")
                for line in data.splitlines():
                    if "UMASK" in line and not line.strip().startswith("#"):
                        try:
                            found_val = int(line.split()[-1], 8)
                        except Exception:
                            continue
        if found_val is None:
            return self.skip(notes="Не удалось определить umask по умолчанию")
        if found_val <= 0o027:
            return self.ok(notes=f"umask={oct(found_val)}")
        return self.fail([
            Finding(
                id=self.id + ":weak",
                description=f"Слабое значение umask ({oct(found_val)})",
                severity=Severity.WARNING,
            )
        ])


class AUTH_1011_SudoersNOPASSWD(Check):
    id = "AUTH-1011"
    title = "Проверка sudoers на наличие NOPASSWD"
    category = "AUTH"

    def run(self, ctx):
        sudoers = Path("/etc/sudoers")
        if not sudoers.exists():
            return self.skip(notes="Файл /etc/sudoers не найден")
        data = sudoers.read_text(encoding="utf-8", errors="ignore")
        if "NOPASSWD" in data:
            return self.fail([
                Finding(
                    id=self.id + ":nopasswd",
                    description="В sudoers найдены правила с NOPASSWD",
                    severity=Severity.HIGH,
                )
            ])
        return self.ok(notes="NOPASSWD в sudoers не обнаружен")