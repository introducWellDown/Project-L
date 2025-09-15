from __future__ import annotations

from .base import Check
from ..core.types import Finding, Severity


class CUST_11000_Template(Check):
    id = "CUST-11000"
    title = "Шаблон пользовательской проверки"
    category = "CUST"

    def run(self, ctx):
        return self.skip(notes="Пользовательская проверка не реализована")


class CUST_11001_Example(Check):
    id = "CUST-11001"
    title = "Пример пользовательской проверки (всегда успешно)"
    category = "CUST"

    def run(self, ctx):
        return self.ok(notes="Пример пользовательской проверки выполнен успешно")


class CUST_11002_ExampleFail(Check):
    id = "CUST-11002"
    title = "Пример пользовательской проверки (всегда ошибка)"
    category = "CUST"

    def run(self, ctx):
        f = Finding(
            id=self.id + ":fail",
            description="Это пример ошибки проверки",
            severity=Severity.SUGGESTION,
        )
        return self.fail([f])
