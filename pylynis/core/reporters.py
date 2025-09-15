from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from .types import Report


class Reporter(ABC):
    @abstractmethod
    def emit(self, report: Report, output_file: Optional[str], quiet: bool = False) -> None:
        """Render and emit report to stdout or file."""
        raise NotImplementedError
