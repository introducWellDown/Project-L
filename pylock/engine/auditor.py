from __future__ import annotations

import importlib
import pkgutil
import socket
from typing import List, Optional

from ..core.runner import run_checks, build_report
from ..engine.context import Context
from ..config.loader import load_profile


def _autodiscover_checks() -> None:
    """
    Автоматически загружает все модули с проверками из пакета pylock.checks.
    Если какой-то модуль не удаётся импортировать, он пропускается.
    """
    pkg_name = "pylock.checks"
    pkg = importlib.import_module(pkg_name)
    for m in pkgutil.walk_packages(pkg.__path__, pkg_name + "."):
        try:
            importlib.import_module(m.name)
        except Exception as e:
            # Не даём упасть всему процессу при ошибке загрузки одного модуля
            print(f"[WARN] Не удалось загрузить модуль проверки {m.name}: {e}")


def _get_primary_ip() -> str:
    """
    Определяет реальный IP адрес устройства (не loopback).
    Использует сокетное подключение к внешнему адресу.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # внешний адрес (Google DNS), пакеты реально не отправляются
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_zone_subject() -> str:
    """
    Определяет IP устройства и сетевую зону.
    Зоны:
      10.0.3.n → DMZ
      10.0.2.n → SIGMA
      10.0.1.n → ALPHA
    """
    ip = _get_primary_ip()

    if ip.startswith("10.0.3."):
        zone = "DMZ"
    elif ip.startswith("10.0.2."):
        zone = "SIGMA"
    elif ip.startswith("10.0.1."):
        zone = "ALPHA"
    else:
        zone = "UNKNOWN"

    return f"Зона {zone}, ip - {ip}"


class Auditor:
    """
    Основной класс для запуска аудита.
    Автоматически подгружает проверки и формирует отчёт.
    """

    def __init__(self, *, verbose: bool = False, debug: bool = False) -> None:
        """
        :param verbose: Если True — подробный вывод.
        :param debug: Если True — вывод отладочной информации.
        """
        self.verbose = verbose
        self.debug = debug
        _autodiscover_checks()

    def run(
        self,
        *,
        subject: Optional[str] = None,
        profile_path: Optional[str] = None,
        tests: Optional[List[str]] = None,
        skip: Optional[List[str]] = None,
    ):
        """
        Запуск аудита.

        :param subject: Объект аудита (по умолчанию вычисляется: зона + ip).
        :param profile_path: Путь к профилю (ini/toml), если задан.
        :param tests: Явный список id проверок, которые нужно выполнить.
        :param skip: Список id проверок, которые нужно пропустить.
        :return: Отчёт (Report).
        """
        if not subject:
            subject = _get_zone_subject()

        profile = load_profile(profile_path)
        ids = tests if tests else (profile.include_tests or None)
        sk = skip if skip else (profile.skip_tests or None)

        ctx = Context(
            subject=subject,
            profile_path=profile_path,
            env={},
            verbose=self.verbose,
            debug=self.debug,
        )
        results = run_checks(ctx, ids=ids, skip=sk)
        return build_report(subject, results)
