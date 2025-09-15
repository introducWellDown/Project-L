from __future__ import annotations

import json
import sys
from typing import Optional

from ..core.reporters import Reporter
from ..core.types import Report


class JSONReporter(Reporter):
    """
    Репортёр, выводящий результаты аудита в формате JSON.
    """

    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
        """
        Сформировать и вывести отчёт в формате JSON.

        :param report: Объект отчёта.
        :param output_file: Если задан — сохраняет отчёт в файл.
        :param quiet: Не используется (оставлен для совместимости).
        """
        payload = {
            "subject": report.subject,
            "meta": report.meta,
            "checks": [
                {
                    "id": c.id,
                    "title": c.title,
                    "category": c.category,
                    "status": c.status,
                    "notes": c.notes,
                    "tags": c.tags,
                    "findings": [
                        {
                            "id": f.id,
                            "description": f.description,
                            "severity": f.severity,
                            "data": f.data,
                        }
                        for f in c.findings
                    ],
                }
                for c in report.checks
            ],
        }

        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)

        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except Exception as e:
                sys.stderr.write(f"[ERROR] Не удалось записать JSON-отчёт в {output_file}: {e}\n")
        else:
            sys.stdout.write(text + "\n")
