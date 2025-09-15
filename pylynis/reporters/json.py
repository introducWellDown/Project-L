from __future__ import annotations

import json
from typing import Optional

from ..core.reporters import Reporter
from ..core.types import Report


class JSONReporter(Reporter):
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
                        } for f in c.findings
                    ],
                } for c in report.checks
            ],
        }
        text = json.dumps(payload, indent=2, sort_keys=True)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            print(text)
