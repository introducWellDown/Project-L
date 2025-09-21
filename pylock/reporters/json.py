from __future__ import annotations

import json
import sys
import requests
from typing import Optional

from ..core.reporters import Reporter
from ..core.types import Report
from ..utils.discovery import discover_server


class JSONReporter(Reporter):
    """
    Репортёр, выводящий результаты аудита в формате JSON
    и (опционально) отправляющий отчёт на сервер.
    """

    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
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

        # 1. Если явно задан файл — пишем туда
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except Exception as e:
                sys.stderr.write(f"[ERROR] Не удалось записать JSON-отчёт в {output_file}: {e}\n")
            return

        # 2. Иначе — пробуем отправить на сервер
        server_url = discover_server()
        if server_url:
            try:
                resp = requests.post(server_url, json=payload, timeout=10)
                print(f"[AGENT] Отчёт отправлен на {server_url}, статус {resp.status_code}")
                return
            except Exception as e:
                sys.stderr.write(f"[AGENT] Ошибка при отправке отчёта: {e}\n")

        # 3. Фоллбек — печатаем в stdout
        sys.stdout.write(text + "\n")
