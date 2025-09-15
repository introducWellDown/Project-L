from __future__ import annotations

from typing import Dict, List, Type

from ..checks.base import Check


_REGISTRY: Dict[str, Type[Check]] = {}


def register(check_cls: Type[Check]) -> None:
    """Register a Check subclass by its id.
    Duplicate ids raise ValueError to avoid clashes.
    """
    cid = check_cls.id
    if cid in _REGISTRY:
        raise ValueError(f"Duplicate check id: {cid}")
    _REGISTRY[cid] = check_cls


def get_checks(ids: List[str] | None = None, skip: List[str] | None = None):
    checks = list(_REGISTRY.values())
    if ids:
        checks = [c for c in checks if c.id in ids]
    if skip:
        checks = [c for c in checks if c.id not in skip]
    checks.sort(key=lambda c: c.id)
    return checks
