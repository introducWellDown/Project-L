from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    SUGGESTION = "suggestion"
    WARNING = "warning"
    ERROR = "error"
    HIGH = "high"


@dataclass(slots=True)
class Finding:
    id: str
    description: str
    severity: Severity
    data: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class CheckResult:
    id: str
    title: str
    category: str
    status: str  # "ok" | "fail" | "skipped"
    findings: List[Finding] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None


@dataclass(slots=True)
class Report:
    subject: str
    checks: List[CheckResult]
    meta: Dict[str, str] = field(default_factory=dict)
