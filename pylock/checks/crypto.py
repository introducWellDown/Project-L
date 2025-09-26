from __future__ import annotations
import os, shutil, subprocess, re

from .base import Check
from ..core.types import Finding, Severity

class SSHStrongCiphers(Check):
    id = "CRYPTO:ssh-ciphers"
    title = "SSH использует стойкие шифры/МАС/ки"
    category = "CRYPTO"

    def run(self, ctx):
        cfgs = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"]
        content = ""
        for p in cfgs:
            if os.path.isfile(p):
                content += open(p, "r", encoding="utf-8", errors="ignore").read()+"\n"
            elif os.path.isdir(p):
                for fn in os.listdir(p):
                    fp = os.path.join(p, fn)
                    if os.path.isfile(fp):
                        content += open(fp, "r", encoding="utf-8", errors="ignore").read()+"\n"
        if not content:
            return self.skip("Конфиг SSH не найден")
        bad = []
        if re.search(r"^\s*Ciphers\s+.*(arcfour|3des|aes128-cbc|aes192-cbc|aes256-cbc)", content, re.M|re.I):
            bad.append("слабые Ciphers")
        if re.search(r"^\s*KexAlgorithms\s+.*(diffie-hellman-group1|group14-sha1)", content, re.M|re.I):
            bad.append("слабые Kex")
        if re.search(r"^\s*MACs\s+.*(hmac-md5)", content, re.M|re.I):
            bad.append("слабые MACs")
        if bad:
            return self.fail([Finding(id=self.id+":weak", description="; ".join(bad), severity=Severity.WARNING)])
        return self.ok()

class FIPSEnabled(Check):
    id = "CRYPTO:fips"
    title = "FIPS режим включён (если требуется)"
    category = "CRYPTO"

    def run(self, ctx):
        # универсальная мягкая проверка
        if os.path.exists("/proc/sys/crypto/fips_enabled"):
            val = open("/proc/sys/crypto/fips_enabled").read().strip()
            if val == "1":
                return self.ok()
            return self.skip("FIPS выключен (для всех сред это не обязательно)")
        return self.skip("FIPS признак не найден")
