from __future__ import annotations

import subprocess
from typing import List


class CommandError(RuntimeError):
    pass


def run_cmd(cmd: List[str], *, check: bool = True, timeout: int | float | None = 10) -> subprocess.CompletedProcess[str]:
    """Run external command safely.
    - No shell=True
    - Captures stdout/stderr as text
    - Optional returncode enforcement via check=True
    """
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        cp = subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr=str(e))
        if check:
            raise CommandError(f"Command not found: {cmd[0]}") from e
        return cp
    except subprocess.TimeoutExpired as e:  # pragma: no cover
        if check:
            raise CommandError(f"Timeout running: {' '.join(cmd)}") from e
        return subprocess.CompletedProcess(cmd, returncode=124, stdout=e.stdout or "", stderr=e.stderr or "")
    if check and proc.returncode != 0:
        raise CommandError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc
