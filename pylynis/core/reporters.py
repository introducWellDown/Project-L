from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from .types import Report


class Reporter(ABC):
    @abstractmethod
    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
        """
        Сформировать и вывести отчёт.

        :param report: Объект отчёта (Report), содержащий результаты проверок.
        :param output_file: Путь к файлу для сохранения (если None — вывод в stdout).
        :param quiet: Если True — минимизировать вывод в консоль.
        """
        raise NotImplementedError
