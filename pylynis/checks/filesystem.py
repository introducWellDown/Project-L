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

class FILE_3007_SudoersPermissions(Check):
    id = "FILE-3007"
    title = "Проверка прав на /etc/sudoers"
    category = "FILE"

    def run(self, ctx):
        path = Path("/etc/sudoers")
        if not path.exists():
            return self.skip(notes="Файл /etc/sudoers отсутствует")
        st = path.stat()
        if st.st_mode & 0o022:
            return self.fail([
                Finding(
                    id=self.id + ":weak",
                    description="/etc/sudoers доступен для записи группой или другими пользователями",
                    severity=Severity.HIGH,
                )
            ])
        return self.ok(notes="Права на /etc/sudoers корректные")


class FILE_3008_LogDirPermissions(Check):
    id = "FILE-3008"
    title = "Проверка прав на /var/log"
    category = "FILE"

    def run(self, ctx):
        path = Path("/var/log")
        if not path.exists():
            return self.skip(notes="Каталог /var/log отсутствует")
        st = path.stat()
        if st.st_mode & 0o002:
            return self.fail([
                Finding(
                    id=self.id + ":worldwritable",
                    description="/var/log доступен для записи всем пользователям",
                    severity=Severity.HIGH,
                )
            ])
        return self.ok(notes="Права на /var/log корректные")

class FILE_3009_EtcIssuePermissions(Check):
    id = "FILE-3009"
    title = "Проверка прав на /etc/issue и /etc/motd"
    category = "FILE"

    def run(self, ctx):
        bad: list[Finding] = []
        for fpath in [Path("/etc/issue"), Path("/etc/motd")]:
            if fpath.exists():
                st = fpath.stat()
                if st.st_mode & 0o002:
                    bad.append(Finding(
                        id=self.id + f":{fpath.name}",
                        description=f"{fpath} доступен для записи всеми пользователями",
                        severity=Severity.WARNING,
                    ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="Права на issue/motd корректные")


class FILE_3010_GroupFilesPermissions(Check):
    id = "FILE-3010"
    title = "Проверка прав на /etc/group и /etc/gshadow"
    category = "FILE"

    def run(self, ctx):
        bad: list[Finding] = []
        for fpath in [Path("/etc/group"), Path("/etc/gshadow")]:
            if fpath.exists():
                st = fpath.stat()
                if st.st_mode & 0o022:
                    bad.append(Finding(
                        id=self.id + f":{fpath.name}",
                        description=f"{fpath} имеет небезопасные права доступа",
                        severity=Severity.HIGH,
                    ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="Права на group/gshadow корректные")

class FILE_3011_TmpMountOptions(Check):
    id = "FILE-3011"
    title = "Проверка опций монтирования для /tmp и /var/tmp"
    category = "FILE"

    def run(self, ctx):
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return self.skip(notes="Не удалось прочитать /proc/mounts")

        bad: list[Finding] = []
        for line in mounts:
            parts = line.split()
            if len(parts) < 4:
                continue
            mnt = parts[1]
            opts = parts[3].split(",")
            if mnt in {"/tmp", "/var/tmp"}:
                for need in ("nodev", "nosuid", "noexec"):
                    if need not in opts:
                        bad.append(Finding(
                            id=self.id + f":{mnt}:{need}",
                            description=f"{mnt} смонтирован без опции {need}",
                            severity=Severity.WARNING,
                        ))
        if bad:
            return self.fail(bad)
        return self.ok(notes="Разделы /tmp и /var/tmp смонтированы с безопасными опциями")

class FILE_3012_VarLogMount(Check):
    id = "FILE-3012"
    title = "Проверка отдельного монтирования /var/log"
    category = "FILE"

    def run(self, ctx):
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return self.skip(notes="Не удалось прочитать /proc/mounts")
        for line in mounts:
            parts = line.split()
            if len(parts) > 1 and parts[1] == "/var/log":
                return self.ok(notes="/var/log смонтирован отдельно")
        return self.fail([
            Finding(
                id=self.id + ":notseparate",
                description="/var/log не смонтирован отдельно",
                severity=Severity.SUGGESTION,
            )
        ])


class FILE_3013_DevShmOptions(Check):
    id = "FILE-3013"
    title = "Проверка опций монтирования для /dev/shm"
    category = "FILE"

    def run(self, ctx):
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return self.skip(notes="Не удалось прочитать /proc/mounts")
        for line in mounts:
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[1] == "/dev/shm":
                opts = parts[3].split(",")
                missing = [o for o in ("nodev", "nosuid", "noexec") if o not in opts]
                if missing:
                    return self.fail([
                        Finding(
                            id=self.id + ":opts",
                            description=f"/dev/shm смонтирован без {','.join(missing)}",
                            severity=Severity.WARNING,
                        )
                    ])
                return self.ok(notes="/dev/shm смонтирован с безопасными опциями")
        return self.skip(notes="/dev/shm не найден в /proc/mounts")
