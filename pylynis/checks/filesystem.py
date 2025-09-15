from __future__ import annotations

import os
from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class FILE_3000_EtcHostsPermissions(Check):
    id = "FILE-3000"
    title = "Проверка прав доступа к /etc/hosts"
    category = "FILE"

    def run(self, ctx):
        fpath = Path("/etc/hosts")
        if not fpath.exists():
            return self.skip(notes="/etc/hosts отсутствует")
        try:
            st = fpath.stat()
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="/etc/hosts недоступен для проверки")
        if st.st_mode & 0o022:
            f = Finding(
                id=self.id + ":perm",
                description="/etc/hosts доступен для записи группой или другими пользователями",
                severity=Severity.WARNING,
            )
            return self.fail([f])
        return self.ok(notes="Права доступа к /etc/hosts в порядке")


class FILE_3001_TmpPermissions(Check):
    id = "FILE-3001"
    title = "Проверка sticky-бита для /tmp"
    category = "FILE"

    def run(self, ctx):
        tmp = Path("/tmp")
        if not tmp.exists():
            return self.skip(notes="/tmp отсутствует")
        try:
            mode = tmp.stat().st_mode
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="/tmp недоступен для проверки")
        if mode & 0o1000:
            return self.ok(notes="/tmp имеет установленный sticky-бит")
        f = Finding(
            id=self.id + ":sticky",
            description="/tmp не имеет sticky-бита",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class FILE_3002_WorldWritableDirs(Check):
    id = "FILE-3002"
    title = "Поиск мировых доступных для записи каталогов без sticky-бита"
    category = "FILE"

    def run(self, ctx):
        bad: list[Finding] = []
        for root, dirs, files in os.walk("/", topdown=True):
            for d in dirs:
                path = Path(root) / d
                try:
                    st = path.lstat()
                except (PermissionError, FileNotFoundError):
                    continue
                if st.st_mode & 0o002 and not (st.st_mode & 0o1000):
                    bad.append(
                        Finding(
                            id=self.id + f":{path}",
                            description=f"Каталог доступен для записи всеми и не имеет sticky-бита: {path}",
                            severity=Severity.WARNING,
                        )
                    )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Опасных каталогов с правом записи для всех не найдено")


class FILE_3003_SuidBinaries(Check):
    id = "FILE-3003"
    title = "Поиск бинарных файлов с установленным SUID"
    category = "FILE"

    def run(self, ctx):
        found = []
        for root, dirs, files in os.walk("/", topdown=True):
            for f in files:
                path = Path(root) / f
                try:
                    st = path.lstat()
                except (PermissionError, FileNotFoundError):
                    continue
                if st.st_mode & 0o4000:
                    found.append(str(path))
        if found:
            return self.ok(notes=f"Найдено {len(found)} SUID-бинарных файлов")
        return self.ok(notes="SUID-бинарные файлы не обнаружены")


class FILE_3004_CoreDumps(Check):
    id = "FILE-3004"
    title = "Проверка ограничений на core dump"
    category = "FILE"

    def run(self, ctx):
        try:
            with open("/proc/sys/kernel/core_pattern", "r", encoding="utf-8") as fh:
                data = fh.read().strip()
        except FileNotFoundError:
            return self.skip(notes="core_pattern недоступен")
        if data == "|/usr/share/apport/apport %p %s %c %P":
            return self.ok(notes="core dump обрабатывается apport")
        if data.startswith("|"):
            return self.ok(notes="core dump перенаправляется в обработчик")
        f = Finding(
            id=self.id + ":enabled",
            description="Core dump может быть включён",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])


class FILE_3005_FstabOptions(Check):
    id = "FILE-3005"
    title = "Проверка опций nodev/nosuid/noexec в /etc/fstab"
    category = "FILE"

    def run(self, ctx):
        fstab = Path("/etc/fstab")
        if not fstab.exists():
            return self.skip(notes="/etc/fstab отсутствует")
        bad: list[Finding] = []
        for line in fstab.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            fields = line.split()
            if len(fields) >= 4:
                mnt, opts = fields[1], fields[3]
                if mnt in ("/home", "/tmp", "/var"):  # критические точки монтирования
                    for needed in ("nodev", "nosuid", "noexec"):
                        if needed not in opts:
                            bad.append(
                                Finding(
                                    id=self.id + f":{mnt}:{needed}",
                                    description=f"{mnt} не содержит опцию {needed} в fstab",
                                    severity=Severity.SUGGESTION,
                                )
                            )
        if bad:
            return self.fail(bad)
        return self.ok(notes="Опции монтирования в fstab выглядят корректно")


class FILE_3006_EtcSecurityLimits(Check):
    id = "FILE-3006"
    title = "Проверка наличия /etc/security/limits.conf"
    category = "FILE"

    def run(self, ctx):
        p = Path("/etc/security/limits.conf")
        if p.exists():
            return self.ok(notes="limits.conf существует")
        return self.skip(notes="limits.conf отсутствует")
