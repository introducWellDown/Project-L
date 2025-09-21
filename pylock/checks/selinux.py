import subprocess
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity


class SEC_1000_SELinux(Check):
    id = "SEC-1000"
    title = "Проверка статуса SELinux"
    category = "SEC"

    def run(self, ctx):
        if not Path("/etc/selinux/config").exists():
            return self.skip(notes="SELinux не установлен")
        try:
            proc = subprocess.run(["getenforce"], capture_output=True, text=True)
            if proc.returncode == 0:
                mode = proc.stdout.strip()
                if mode == "Enforcing":
                    return self.ok(notes="SELinux в режиме Enforcing")
                return self.fail([
                    Finding(
                        id=self.id + ":mode",
                        description=f"SELinux в режиме {mode}",
                        severity=Severity.WARNING,
                    )
                ])
        except Exception:
            return self.skip(notes="Не удалось определить статус SELinux")
        return self.skip(notes="SELinux установлен, но не удалось проверить режим")


class SEC_1001_AppArmor(Check):
    id = "SEC-1001"
    title = "Проверка статуса AppArmor"
    category = "SEC"

    def run(self, ctx):
        if not Path("/etc/apparmor").exists():
            return self.skip(notes="AppArmor не установлен")
        try:
            proc = subprocess.run(["aa-status"], capture_output=True, text=True)
            if proc.returncode == 0:
                data = proc.stdout
                if "enforce mode" in data.lower():
                    return self.ok(notes="AppArmor профили в enforce mode")
                return self.fail([
                    Finding(
                        id=self.id + ":notenforce",
                        description="AppArmor установлен, но профили не в enforce режиме",
                        severity=Severity.WARNING,
                    )
                ])
        except Exception:
            return self.skip(notes="Не удалось определить статус AppArmor")
        return self.skip(notes="AppArmor установлен, но проверка не удалась")
