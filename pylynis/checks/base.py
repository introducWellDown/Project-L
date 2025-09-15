from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..core.types import CheckResult, Finding
from ..engine.context import Context
from ..core import registry


class Check(ABC):
    """Базовый класс для всех проверок"""

    id: str               # Уникальный идентификатор проверки
    title: str            # Человекочитаемое название проверки
    category: str         # Категория (например: FILE, AUTH, NETWORK)
    tags: List[str] = []  # Дополнительные теги

    def __init_subclass__(cls, **kwargs):
        """Автоматическая регистрация подклассов в реестре"""
        super().__init_subclass__(**kwargs)
        if getattr(cls, "id", None):
            registry.register(cls)

    @abstractmethod
    def run(self, ctx: Context) -> CheckResult:
        """Основной метод, который выполняет проверку и возвращает результат"""
        raise NotImplementedError("Метод run() должен быть реализован в подклассе")

    def ok(self, notes: str | None = None) -> CheckResult:
        """Успешный результат проверки"""
        return CheckResult(
            id=self.id or "UNKNOWN",
            title=self.title or "Без названия",
            category=self.category or "UNCATEGORIZED",
            status="ok",
            notes=notes,
        )

    def fail(self, findings: List[Finding], notes: str | None = None) -> CheckResult:
        """Провал проверки с найденными проблемами"""
        return CheckResult(
            id=self.id or "UNKNOWN",
            title=self.title or "Без названия",
            category=self.category or "UNCATEGORIZED",
            status="fail",
            findings=findings or [],
            notes=notes,
        )

    def skip(self, notes: str | None = None) -> CheckResult:
        """Пропуск проверки (например, файл отсутствует или нет доступа)"""
        return CheckResult(
            id=self.id or "UNKNOWN",
            title=self.title or "Без названия",
            category=self.category or "UNCATEGORIZED",
            status="skipped",
            notes=notes,
        )
