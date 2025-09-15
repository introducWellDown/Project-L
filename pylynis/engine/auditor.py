from __future__ import annotations

import importlib
import pkgutil
from typing import List, Optional

from ..core.runner import run_checks, build_report
from ..engine.context import Context
from ..config.loader import load_profile


def _autodiscover_checks() -> None:
    pkg_name = "pylynis.checks"
    pkg = importlib.import_module(pkg_name)
    for m in pkgutil.walk_packages(pkg.__path__, pkg_name + "."):
        importlib.import_module(m.name)


class Auditor:
    def __init__(self, *, verbose: bool = False, debug: bool = False) -> None:
        self.verbose = verbose
        self.debug = debug
        _autodiscover_checks()

    def run(
        self,
        *,
        subject: str = "system",
        profile_path: Optional[str] = None,
        tests: Optional[List[str]] = None,
        skip: Optional[List[str]] = None,
    ):
        profile = load_profile(profile_path)
        ids = tests if tests else (profile.include_tests or None)
        sk = skip if skip else (profile.skip_tests or None)

        ctx = Context(subject=subject, profile_path=profile_path, env={}, verbose=self.verbose, debug=self.debug)
        results = run_checks(ctx, ids=ids, skip=sk)
        return build_report(subject, results)
