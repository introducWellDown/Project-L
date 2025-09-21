from __future__ import annotations

import platform
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class KRNL_4000_KernelVersion(Check):
    id = "KRNL-4000"
    title = "Определение версии ядра"
    category = "KRNL"

    def run(self, ctx):
        try:
            rel = platform.release()
        except Exception as e:
            f = Finding(
                id=self.id + ":error",
                description=f"Ошибка при определении версии ядра: {e}",
                severity=Severity.SUGGESTION,
            )
            return self.fail([f])
        if rel:
            return self.ok(notes=f"Версия ядра: {rel}")
        f = Finding(
            id=self.id + ":unknown",
            description="Не удалось определить версию ядра",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class KRNL_4001_CheckArch(Check):
    id = "KRNL-4001"
    title = "Проверка архитектуры системы"
    category = "KRNL"

    def run(self, ctx):
        try:
            arch = platform.machine()
        except Exception:
            return self.skip(notes="Не удалось определить архитектуру")
        if arch:
            return self.ok(notes=f"Архитектура: {arch}")
        return self.skip(notes="Архитектура неизвестна")


class KRNL_4002_RandomizeVaSpace(Check):
    id = "KRNL-4002"
    title = "Проверка kernel.randomize_va_space (ASLR)"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/randomize_va_space")
        if not path.exists():
            return self.skip(notes="randomize_va_space недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать randomize_va_space")
        if val in {"1", "2"}:
            return self.ok(notes=f"ASLR включён (randomize_va_space={val})")
        f = Finding(
            id=self.id + ":disabled",
            description="ASLR выключен",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class KRNL_4003_SysRq(Check):
    id = "KRNL-4003"
    title = "Проверка kernel.sysrq"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/sysrq")
        if not path.exists():
            return self.skip(notes="sysrq недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать sysrq")
        if val == "0":
            return self.ok(notes="sysrq отключён")
        f = Finding(
            id=self.id + ":enabled",
            description=f"sysrq включён (значение: {val})",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class KRNL_4004_DmesgRestrict(Check):
    id = "KRNL-4004"
    title = "Проверка kernel.dmesg_restrict"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/dmesg_restrict")
        if not path.exists():
            return self.skip(notes="dmesg_restrict недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать dmesg_restrict")
        if val == "1":
            return self.ok(notes="dmesg ограничен (restricted)")
        f = Finding(
            id=self.id + ":off",
            description="dmesg не ограничен",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class KRNL_4005_KptrRestrict(Check):
    id = "KRNL-4005"
    title = "Проверка kernel.kptr_restrict"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/kptr_restrict")
        if not path.exists():
            return self.skip(notes="kptr_restrict недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать kptr_restrict")
        if val == "1":
            return self.ok(notes="kptr_restrict включён")
        f = Finding(
            id=self.id + ":off",
            description="kptr_restrict выключен",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class KRNL_4006_ModuleLoading(Check):
    id = "KRNL-4006"
    title = "Проверка kernel.modules_disabled"
    category = "KRNL"

    def run(self, ctx):
        path = Path("/proc/sys/kernel/modules_disabled")
        if not path.exists():
            return self.skip(notes="modules_disabled недоступен")
        try:
            val = path.read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return self.skip(notes="Не удалось прочитать modules_disabled")
        if val == "1":
            return self.ok(notes="Загрузка модулей отключена")
        return self.ok(notes="Загрузка модулей разрешена")
