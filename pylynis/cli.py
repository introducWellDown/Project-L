from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .engine.auditor import Auditor
from .reporters.console import ConsoleReporter
from .reporters.json import JSONReporter
from .reporters.txt import TXTReporter
from .config.loader import load_profile


FORMATS = {"text": TXTReporter, "console": ConsoleReporter, "json": JSONReporter}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pylynis",
        description="Python port of Lynis — security auditing tool (experimental)",
    )
    parser.add_argument("command", choices=["audit", "scan", "update", "show-report"], help="Command")
    parser.add_argument("subject", nargs="?", default="system", help="What to audit (system)")
    parser.add_argument("--profile", dest="profile", help="Path to profile (.prf/.ini/.toml)")
    parser.add_argument("--tests", dest="tests", help="Comma-separated list of tests to run")
    parser.add_argument("--skip", dest="skip", help="Comma-separated list of tests to skip")
    parser.add_argument("--format", dest="fmt", default="text", choices=list(FORMATS.keys()))
    parser.add_argument("--report-file", dest="report_file", help="Path to save report")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {"audit", "scan"}:
        profile = load_profile(args.profile)
        tests = args.tests.split(",") if args.tests else profile.include_tests
        skip = args.skip.split(",") if args.skip else profile.skip_tests
        auditor = Auditor(verbose=args.verbose, debug=args.debug)
        report = auditor.run(subject=args.subject, profile_path=args.profile, tests=tests, skip=skip)
        ReporterCls = FORMATS.get(args.fmt, TXTReporter)
        reporter = ReporterCls()
        reporter.emit(report, output_file=args.report_file, quiet=args.quiet)
        return 0
    if args.command == "update":
        print("update: not implemented yet", file=sys.stderr)
        return 2
    if args.command == "show-report":
        print("show-report: not implemented yet", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
