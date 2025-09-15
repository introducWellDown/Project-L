from __future__ import annotations

import shutil

from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd


class NETW_1000_OpenPorts(Check):
    id = "NETW-1000"
    title = "Check open TCP ports"
    category = "NETWORK"
    tags = ["network", "ports"]

    def run(self, ctx):  # type: ignore[override]
        tool = shutil.which("ss") or shutil.which("netstat")
        if not tool:
            f = Finding(id=self.id+":missing", description="Neither ss nor netstat found", severity=Severity.WARNING)
            return self.skip(notes=f.description)

        if "ss" in tool:
            proc = run_cmd([tool, "-tln"], check=False)
        else:
            proc = run_cmd([tool, "-tln"], check=False)

        if proc.returncode != 0:
            f = Finding(id=self.id+":fail", description="Failed to list open ports", severity=Severity.ERROR)
            return self.fail([f])

        lines = [ln for ln in proc.stdout.splitlines() if ":" in ln]
        notes = f"Found {len(lines)} listening TCP sockets"
        return self.ok(notes=notes)
