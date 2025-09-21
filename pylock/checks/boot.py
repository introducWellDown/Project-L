from __future__ import annotations

from pathlib import Path

from .base import Check
from ..core.types import Finding, Severity


class BOOT_2000_GrubConfig(Check):
    id = "BOOT-2000"
    title = "Проверка конфигурации GRUB"
    category = "BOOT"

    def run(self, ctx):
        grub_cfg = Path("/boot/grub/grub.cfg")
        grub2_cfg = Path("/boot/grub2/grub.cfg")
        if grub_cfg.exists():
            return self.ok(notes=f"Файл конфигурации найден: {grub_cfg}")
        if grub2_cfg.exists():
            return self.ok(notes=f"Файл конфигурации найден: {grub2_cfg}")
        f = Finding(
            id=self.id + ":missing",
            description="Файл конфигурации GRUB не найден",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class BOOT_2001_GrubPassword(Check):
    id = "BOOT-2001"
    title = "Проверка наличия пароля в GRUB"
    category = "BOOT"

    def run(self, ctx):
        for candidate in [Path("/boot/grub/grub.cfg"), Path("/boot/grub2/grub.cfg")]:
            if candidate.exists():
                try:
                    data = candidate.read_text(encoding="utf-8", errors="ignore")
                except (PermissionError, FileNotFoundError):
                    return self.skip(notes=f"Файл {candidate} недоступен для проверки")
                if "set superusers" in data and "password" in data:
                    return self.ok(notes="Пароль GRUB настроен")
                f = Finding(
                    id=self.id + ":nopass",
                    description="Пароль GRUB не найден",
                    severity=Severity.WARNING,
                )
                return self.fail([f])
        return self.skip(notes="Файл конфигурации GRUB не найден")


class BOOT_2002_Initramfs(Check):
    id = "BOOT-2002"
    title = "Проверка наличия initramfs/initrd"
    category = "BOOT"

    def run(self, ctx):
        boot = Path("/boot")
        if not boot.exists():
            return self.skip(notes="Каталог /boot отсутствует")
        imgs = list(boot.glob("initramfs-*")) + list(boot.glob("initrd-*"))
        if imgs:
            return self.ok(notes=f"Найдено {len(imgs)} образов initramfs/initrd")
        f = Finding(
            id=self.id + ":none",
            description="В /boot не найдено initramfs/initrd",
            severity=Severity.WARNING,
        )
        return self.fail([f])


class BOOT_2003_SecureBoot(Check):
    id = "BOOT-2003"
    title = "Проверка включённого Secure Boot (EFI)"
    category = "BOOT"

    def run(self, ctx):
        efivar = Path("/sys/firmware/efi/efivars")
        if not efivar.exists():
            return self.skip(notes="Система не EFI")
        for p in efivar.glob("SecureBoot-*"):
            try:
                data = p.read_bytes()
                if data and data[-1] == 1:
                    return self.ok(notes="Secure Boot включён")
                else:
                    f = Finding(
                        id=self.id + ":off",
                        description="Secure Boot выключен",
                        severity=Severity.WARNING,
                    )
                    return self.fail([f])
            except (PermissionError, FileNotFoundError):
                continue
            except Exception as e:
                return self.skip(notes=f"Ошибка при чтении {p}: {e}")
        return self.skip(notes="Переменная SecureBoot не найдена")


class BOOT_2004_BootloaderOwner(Check):
    id = "BOOT-2004"
    title = "Проверка владельца каталога загрузчика"
    category = "BOOT"

    def run(self, ctx):
        for path in [Path("/boot/grub"), Path("/boot/grub2")]:
            if path.exists():
                try:
                    st = path.stat()
                except (PermissionError, FileNotFoundError):
                    return self.skip(notes=f"Каталог {path} недоступен для проверки")
                if st.st_uid != 0:
                    f = Finding(
                        id=self.id + ":owner",
                        description=f"{path} не принадлежит пользователю root",
                        severity=Severity.HIGH,
                    )
                    return self.fail([f])
                return self.ok(notes=f"{path} принадлежит root")
        return self.skip(notes="Каталог загрузчика grub не найден")


class BOOT_2005_BootMountPermissions(Check):
    id = "BOOT-2005"
    title = "Проверка опций монтирования раздела /boot"
    category = "BOOT"

    def run(self, ctx):
        try:
            mnt = Path("/proc/mounts").read_text(encoding="utf-8")
        except (PermissionError, FileNotFoundError):
            return self.skip(notes="/proc/mounts недоступен")
        for line in mnt.splitlines():
            if " /boot " in line:
                try:
                    opts = line.split()[3].split(",")
                except IndexError:
                    return self.skip(notes="Не удалось разобрать строку монтирования /boot")
                if "nosuid" in opts and "nodev" in opts:
                    return self.ok(notes="/boot смонтирован с nosuid,nodev")
                f = Finding(
                    id=self.id + ":opts",
                    description="/boot смонтирован без nosuid/nodev",
                    severity=Severity.SUGGESTION,
                )
                return self.fail([f])
        return self.skip(notes="Раздел /boot не смонтирован отдельно")
