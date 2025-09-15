from __future__ import annotations

from typing import Dict, List, Type

from ..checks.base import Check


# Реестр всех зарегистрированных проверок
_REGISTRY: Dict[str, Type[Check]] = {}


def register(check_cls: Type[Check]) -> None:
    """
    Регистрация подкласса Check по его id.
    Если id дублируется — выбрасывается ValueError, чтобы избежать конфликтов.
    """
    cid = getattr(check_cls, "id", None)
    if not isinstance(cid, str) or not cid:
        raise ValueError(f"Неверный id у проверки: {check_cls}")
    if cid in _REGISTRY:
        raise ValueError(f"Дубликат id проверки: {cid}")
    _REGISTRY[cid] = check_cls


def get_checks(ids: List[str] | None = None, skip: List[str] | None = None) -> List[Type[Check]]:
    """
    Получить список зарегистрированных проверок.

    :param ids: Список id проверок, которые нужно выбрать (если None — все).
    :param skip: Список id проверок, которые нужно исключить.
    :return: Отсортированный список классов проверок.
    """
    checks = list(_REGISTRY.values())
    if ids:
        checks = [c for c in checks if c.id in ids]
    if skip:
        checks = [c for c in checks if c.id not in skip]
    checks.sort(key=lambda c: c.id)
    return checks
