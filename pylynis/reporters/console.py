from __future__ import annotations

import sys
from typing import Optional

from ..core.reporters import Reporter
from ..core.types import Report


class ConsoleReporter(Reporter):
    """
    Репортёр, выводящий результаты аудита в консоль или в файл.
    """

    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
        """
        Сформировать и вывести отчёт.

        :param report: Объект отчёта.
        :param output_file: Если задан — сохраняет отчёт в файл.
        :param quiet: Если True — не выводить заголовок.
        """
        out: list[str] = []

        if not quiet:
            out.append(f"Объект аудита: {report.subject}")

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
            try:
                with open(output_file, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except Exception as e:
                sys.stderr.write(f"[ERROR] Не удалось записать файл отчёта {output_file}: {e}\n")
        else:
            sys.stdout.write(text)
