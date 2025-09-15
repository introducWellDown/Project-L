from __future__ import annotations

import subprocess
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class PROC_7000_RootProcesses(Check):
    id = "PROC-7000"
    title = "Проверка процессов, запущенных от root"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "user,comm"], text=True)
        except Exception:
            return self.skip(notes="Команда ps недоступна")
        root_procs = [line for line in output.splitlines() if line.startswith("root ")]
        return self.ok(notes=f"Процессов от root: {len(root_procs)}")


class PROC_7001_ZombieProcesses(Check):
    id = "PROC-7001"
    title = "Проверка на зомби-процессы"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "stat,comm"], text=True)
        except Exception:
            return self.skip(notes="Команда ps недоступна")
        zombies = [line for line in output.splitlines() if line.startswith("Z")]  # STAT Z
        if zombies:
            f = Finding(
                id=self.id + ":zombies",
                description=f"Обнаружено зомби-процессов: {len(zombies)}",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        return self.ok(notes="Зомби-процессы отсутствуют")


class PROC_7002_SuspiciousTmpExec(Check):
    id = "PROC-7002"
    title = "Проверка процессов, запущенных из /tmp"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "pid,comm,args"], text=True)
        except Exception:
            return self.skip(notes="Команда ps недоступна")
        bad: list[Finding] = []
        for line in output.splitlines():
            if "/tmp/" in line:
                bad.append(
                    Finding(
                        id=self.id + ":tmp",
                        description=f"Процесс запущен из /tmp: {line}",
                        severity=Severity.HIGH,
                    )
                )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Процессов, запущенных из /tmp, не найдено")


class PROC_7003_OrphanedProcesses(Check):
    id = "PROC-7003"
    title = "Проверка осиротевших процессов (ppid=1)"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "ppid,comm"], text=True)
        except Exception:
            return self.skip(notes="Команда ps недоступна")
        orphans = [line for line in output.splitlines() if line.strip().startswith("1 ")]
        if orphans:
            return self.ok(notes=f"Осиротевших процессов: {len(orphans)}")
        return self.ok(notes="Осиротевшие процессы отсутствуют")


class PROC_7004_LongRunningHighCpu(Check):
    id = "PROC-7004"
    title = "Проверка процессов с высоким использованием CPU"
    category = "PROC"

    def run(self, ctx):
        try:
            output = subprocess.check_output(["ps", "-eo", "%cpu,comm"], text=True)
        except Exception:
            return self.skip(notes="Команда ps недоступна")
        bad: list[Finding] = []
        for line in output.splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    cpu = float(parts[0])
                    if cpu > 80.0:
                        bad.append(
                            Finding(
                                id=self.id + ":cpu",
                                description=f"Высокая загрузка CPU: {line}",
                                severity=Severity.SUGGESTION,
                            )
                        )
                except ValueError:
                    continue
        if bad:
            return self.fail(bad)
        return self.ok(notes="Процессов с высокой нагрузкой на CPU не найдено")


class PROC_7005_UnknownUsers(Check):
    id = "PROC-7005"
    title = "Проверка процессов с неизвестными пользователями"
    category = "PROC"

    def run(self, ctx):
        try:
            passwd_lines = Path("/etc/passwd").read_text(encoding="utf-8").splitlines()
            known_users = {u.split(":", 1)[0] for u in passwd_lines if u and ":" in u}
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="Не удалось прочитать /etc/passwd")
        try:
            output = subprocess.check_output(["ps", "-eo", "user,comm"], text=True)
        except Exception:
            return self.skip(notes="Команда ps недоступна")
        bad: list[Finding] = []
        for line in output.splitlines()[1:]:
            parts = line.split(None, 1)
            if not parts:
                continue
            user = parts[0]
            if user not in known_users:
                bad.append(
                    Finding(
                        id=self.id + ":unkusr",
                        description=f"Процесс запущен от неизвестного пользователя: {user}",
                        severity=Severity.WARNING,
                    )
                )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Все пользователи процессов валидны")
