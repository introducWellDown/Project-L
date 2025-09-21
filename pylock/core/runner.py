from __future__ import annotations

from typing import List

from .types import CheckResult, Report
from ..engine.context import Context
from .registry import get_checks


def run_checks(ctx: Context, ids: list[str] | None, skip: list[str] | None) -> List[CheckResult]:
    """
    Запускает все проверки и возвращает список результатов.

    :param ctx: Контекст выполнения (например, настройки запуска).
    :param ids: Список id проверок, которые нужно выполнить (если None — все).
    :param skip: Список id проверок, которые нужно пропустить.
    :return: Список объектов CheckResult.
    """
    results: List[CheckResult] = []
    for CheckCls in get_checks(ids=ids, skip=skip):
        try:
            check = CheckCls()
            res = check.run(ctx)
            results.append(res)
        except Exception as e:
            # Перехватываем ошибки, чтобы падение одной проверки не остановило все
            results.append(
                CheckResult(
                    id=getattr(CheckCls, "id", "unknown"),
                    title=getattr(CheckCls, "title", "Неизвестная проверка"),
                    category=getattr(CheckCls, "category", "UNKNOWN"),
                    status="error",
                    notes=f"Ошибка выполнения проверки: {e}",
                )
            )
    return results


def build_report(subject: str, results: List[CheckResult]) -> Report:
    """
    Формирует итоговый отчёт из результатов проверок.

    :param subject: Заголовок/тема отчёта (например, имя хоста).
    :param results: Список результатов проверок.
    :return: Объект Report.
    """
    meta = {"host": ctx_hostname_safe()}
    return Report(subject=subject, checks=results, meta=meta)


def ctx_hostname_safe() -> str:
    """
    Безопасное получение имени хоста.
    Если недоступно — возвращает 'unknown'.
    """
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
