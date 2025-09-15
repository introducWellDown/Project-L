from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..core.types import CheckResult, Finding, Severity
from ..engine.context import Context
from ..core import registry


class Check(ABC):
    id: str
    title: str
    category: str
    tags: List[str] = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "id", None):
            registry.register(cls)

    @abstractmethod
    def run(self, ctx: Context) -> CheckResult:
        raise NotImplementedError

    def ok(self, notes: str | None = None) -> CheckResult:
        return CheckResult(id=self.id, title=self.title, category=self.category, status="ok", notes=notes)

    def fail(self, findings: List[Finding], notes: str | None = None) -> CheckResult:
        return CheckResult(id=self.id, title=self.title, category=self.category, status="fail", findings=findings, notes=notes)

    def skip(self, notes: str | None = None) -> CheckResult:
        return CheckResult(id=self.id, title=self.title, category=self.category, status="skipped", notes=notes)
