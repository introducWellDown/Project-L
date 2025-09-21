from __future__ import annotations

import argparse
import sys
import time
import subprocess
from typing import List, Optional

import requests

from .engine.auditor import Auditor
from .config.loader import load_profile
from .utils.discovery import discover_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pylock",
        description="Python port of Lynis — security auditing tool (experimental)",
    )
    parser.add_argument(
        "command",
        choices=["audit", "agentd", "ui"],
        help="Команда для запуска",
    )
    parser.add_argument(
        "subject", nargs="?", default=None, help="Что проверять (по умолчанию: зона+ip)"
    )
    parser.add_argument("--profile", dest="profile", help="Path to profile (.prf/.ini/.toml)")
    parser.add_argument("--tests", dest="tests", help="Comma-separated list of tests to run")
    parser.add_argument("--skip", dest="skip", help="Comma-separated list of tests to skip")
    parser.add_argument("--interval", type=int, default=300, help="Интервал между аудитами (сек)")

    return parser


def run_audit(args) -> dict:
    """Запускает аудит и возвращает отчёт в виде dict"""
    profile = load_profile(args.profile)
    tests = args.tests.split(",") if args.tests else profile.include_tests
    skip = args.skip.split(",") if args.skip else profile.skip_tests

    auditor = Auditor(verbose=False, debug=False)

    subject = None if args.subject == "checks" else args.subject

    report = auditor.run(
        subject=subject,
        profile_path=args.profile,
        tests=tests,
        skip=skip,
    )

    payload = {
        "subject": report.subject,
        "meta": report.meta,
        "checks": [
            {
                "id": c.id,
                "status": c.status,
                "title": c.title,
                "notes": c.notes,
                "findings": [
                    {
                        "id": f.id,
                        "description": f.description,
                        "severity": f.severity,
                    }
                    for f in c.findings
                ],
            }
            for c in report.checks
        ],
    }
    return payload


def send_report(payload: dict, server_url: str) -> bool:
    try:
        resp = requests.post(server_url, json=payload, timeout=10)
        print(f"[AGENT] Отчёт отправлен на {server_url}, статус {resp.status_code}")
        return resp.status_code == 200
    except Exception as e:
        print(f"[AGENT] Ошибка при отправке отчёта: {e}")
        return False


def run_agentd(args):
    """Фоновый агент"""
    server_url = None
    while True:
        payload = run_audit(args)

        if not server_url:
            server_url = discover_server(timeout=args.interval)

        if server_url:
            ok = send_report(payload, server_url)
            if not ok:
                print("[AGENT] Сервер недоступен, сбрасываю адрес, ищу HI заново...")
                server_url = None

        time.sleep(args.interval)


def run_ui():
    """Запуск streamlit дашборда"""
    try:
        subprocess.run(
            ["streamlit", "run", "pylock/ui_streamlit.py"],
            check=True,
        )
    except FileNotFoundError:
        print("[ERROR] Streamlit не установлен. Установи: pip install streamlit")
        sys.exit(1)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "audit":
        payload = run_audit(args)
        server_url = discover_server(timeout=10)
        if server_url:
            send_report(payload, server_url)
        else:
            print("[AGENT] Сервер не найден, отчёт не отправлен")
        return 0

    if args.command == "agentd":
        print(f"[AGENTD] Запуск демона, интервал {args.interval} сек.")
        run_agentd(args)
        return 0

    if args.command == "ui":
        run_ui()
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
