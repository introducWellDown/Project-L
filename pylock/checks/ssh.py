from __future__ import annotations

from pathlib import Path
import subprocess
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

class SSH_8007_SshAlgorithms(Check):
    id = "SSH-8007"
    title = "Проверка sshd_config на устаревшие алгоритмы"
    category = "SSH"

    def run(self, ctx):
        cfg = Path("/etc/ssh/sshd_config")
        if not cfg.exists():
            return self.skip(notes="sshd_config не найден")
        data = cfg.read_text(encoding="utf-8", errors="ignore")
        bad_algos = ["arcfour", "3des", "blowfish", "aes128-cbc", "hmac-md5"]
        findings: list[Finding] = []

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(bad in line.lower() for bad in bad_algos):
                findings.append(Finding(
                    id=self.id + ":weak",
                    description=f"Обнаружен устаревший алгоритм в конфиге: {line}",
                    severity=Severity.HIGH,
                ))
        if findings:
            return self.fail(findings)
        return self.ok(notes="Устаревшие алгоритмы в sshd_config не найдены")


class SSH_8008_SshKeyStrength(Check):
    id = "SSH-8008"
    title = "Проверка прочности SSH-ключей в /etc/ssh"
    category = "SSH"

    def run(self, ctx):
        ssh_dir = Path("/etc/ssh")
        if not ssh_dir.exists():
            return self.skip(notes="Каталог /etc/ssh отсутствует")
        findings: list[Finding] = []
        for keyfile in ssh_dir.glob("ssh_host_*_key.pub"):
            try:
                out = subprocess.check_output(["ssh-keygen", "-lf", str(keyfile)], text=True)
                bits = int(out.split()[0])
                if bits < 2048:
                    findings.append(Finding(
                        id=self.id + f":{keyfile.name}",
                        description=f"Слабый SSH-ключ {keyfile.name} ({bits} бит)",
                        severity=Severity.HIGH,
                    ))
            except Exception:
                continue
        if findings:
            return self.fail(findings)
        return self.ok(notes="Все SSH-ключи имеют достаточную длину")

class SSH_8009_SshCiphers(Check):
    id = "SSH-8009"
    title = "Проверка списка Ciphers в sshd_config"
    category = "SSH"

    def run(self, ctx):
        cfg = Path("/etc/ssh/sshd_config")
        if not cfg.exists():
            return self.skip(notes="sshd_config не найден")
        data = cfg.read_text(encoding="utf-8", errors="ignore")
        for line in data.splitlines():
            if line.strip().startswith("Ciphers"):
                if any(x in line for x in ["arcfour", "3des", "aes128-cbc"]):
                    return self.fail([
                        Finding(
                            id=self.id + ":weak",
                            description=f"Обнаружены слабые Ciphers: {line}",
                            severity=Severity.HIGH,
                        )
                    ])
                return self.ok(notes="Ciphers заданы и безопасны")
        return self.skip(notes="Ciphers не заданы в sshd_config")


class SSL_1000_CertExpiry(Check):
    id = "SSL-1000"
    title = "Проверка срока действия TLS-сертификатов"
    category = "SSL"

    def run(self, ctx):
        certs = list(Path("/etc/ssl/certs").glob("*.pem"))
        if not certs:
            return self.skip(notes="Сертификаты не найдены")
        findings: list[Finding] = []
        for cert in certs:
            try:
                out = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-noout", "-enddate"], text=True)
                enddate = out.strip().split("=", 1)[1]
                # просто пишем дату, без сложного парсинга (иначе нужна dateutil)
                findings.append(Finding(
                    id=self.id + f":{cert.name}",
                    description=f"Сертификат {cert.name} истекает {enddate}",
                    severity=Severity.SUGGESTION,
                ))
            except Exception:
                continue
        if findings:
            return self.fail(findings)
        return self.ok(notes="Сертификаты проверены")
