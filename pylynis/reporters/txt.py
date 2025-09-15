from __future__ import annotations

import sys
from typing import Optional

from ..core.reporters import Reporter
from ..core.types import Report


class TXTReporter(Reporter):
    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
        lines: list[str] = []
        if not quiet:
            lines.append(f"Subject: {report.subject}")
            lines.append("="*60)
        grouped: dict[str, list] = {}
        for chk in report.checks:
            grouped.setdefault(chk.category, []).append(chk)
        for cat, checks in grouped.items():
            lines.append(f"[{cat}]")
            for c in checks:
                status = c.status.upper()
                line = f" {c.id:<10} {status:<8} {c.title}"
                if c.notes:
                    line += f" — {c.notes}"
                lines.append(line)
            lines.append("")
        text = "\n".join(lines) + "\n"
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            sys.stdout.write(text)
