from __future__ import annotations

from typing import List

from .types import CheckResult, Report
from ..engine.context import Context
from .registry import get_checks


def run_checks(ctx: Context, ids: list[str] | None, skip: list[str] | None) -> List[CheckResult]:
    results: List[CheckResult] = []
    for CheckCls in get_checks(ids=ids, skip=skip):
        check = CheckCls()
        res = check.run(ctx)
        results.append(res)
    return results


def build_report(subject: str, results: List[CheckResult]) -> Report:
    meta = {"host": ctx_hostname_safe()}
    return Report(subject=subject, checks=results, meta=meta)


def ctx_hostname_safe() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
