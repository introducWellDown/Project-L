from __future__ import annotations
from pathlib import Path
from .base import Check
from ..core.types import Finding, Severity
from ..utils.cmd import run_cmd

class NETW_5000_OpenTCPPorts(Check):
    id="NETW-5000"; title="Enumerate listening TCP ports"; category="NETW"
    def run(self, ctx):
        proc = run_cmd(["ss","-tln"], check=False)
        if proc.returncode==0 and proc.stdout:
            return self.ok(notes=f"ss output lines: {len(proc.stdout.splitlines())}")
        np = run_cmd(["netstat","-tln"], check=False)
        if np.returncode==0 and np.stdout:
            return self.ok(notes=f"netstat output lines: {len(np.stdout.splitlines())}")
        f = Finding(id=self.id+":no_tool", description="Neither ss nor netstat available", severity=Severity.WARNING)
        return self.fail([f])
