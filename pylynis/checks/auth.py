from __future__ import annotations

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class AUTH_1000_SudoVersion(Check):
    id = "AUTH-1000"
    title = "Check sudo availability and version"
    category = "AUTH"
    tags = ["sudo", "auth"]

    def run(self, ctx):  # type: ignore[override]
        proc = run_cmd(["sudo", "--version"], check=False)
        if proc.returncode != 0:
            f = Finding(id=self.id + ":sudo_missing", description="sudo not found or not executable", severity=Severity.WARNING)
            return self.fail([f], notes="Install sudo or verify PATH/permissions")
        line = proc.stdout.splitlines()[0] if proc.stdout else ""
        if "version" in line.lower():
            return self.ok(notes=line.strip())
        else:
            f = Finding(id=self.id + ":sudo_unknown", description="Unable to parse sudo version", severity=Severity.SUGGESTION)
            return self.fail([f])
