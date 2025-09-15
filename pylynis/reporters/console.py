from __future__ import annotations

import sys
from typing import Optional

from ..core.reporters import Reporter
from ..core.types import Report


class ConsoleReporter(Reporter):
    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
        out = []
        if not quiet:
            out.append(f"Subject: {report.subject}")
        for c in report.checks:
            status = c.status.upper()
            line = f"[{status}] {c.id} {c.title}"
            if c.notes:
                line += f" — {c.notes}"
            out.append(line)
            for f in c.findings:
                out.append(f"  - {f.severity}: {f.description}")
        text = "\n".join(out) + "\n"
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            sys.stdout.write(text)
