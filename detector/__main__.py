"""
Command-line entry point.

    python -m detector sample_logs/auth.log
    python -m detector sample_logs/auth.log --json report.json
    python -m detector /var/log/auth.log --year 2026 --fail-on-critical

Exit codes (handy for scripts and CI pipelines):
    0  ran fine (or no CRITICAL alerts when --fail-on-critical is set)
    1  bad input (file missing, etc.)
    2  CRITICAL alert found and --fail-on-critical was set
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from detector.parser import parse_file
from detector.report import format_report, should_use_color, write_json
from detector.rules import run_all_rules


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detector",
        description="Detect brute-force, password-spray, and possible break-ins in Linux SSH auth logs.",
    )
    p.add_argument("logfile", help="path to an auth.log file")
    p.add_argument("--json", metavar="PATH", help="also write the results to a JSON file")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year to assume for log timestamps (syslog omits it)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="exit with code 2 if any CRITICAL alert is found")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    path = Path(args.logfile)
    if not path.is_file():
        print(f"error: log file not found: {path}", file=sys.stderr)
        return 1

    events = parse_file(path, year=args.year)
    alerts = run_all_rules(events)

    color = should_use_color() and not args.no_color
    print(format_report(events, alerts, color=color))

    if args.json:
        write_json(args.json, events, alerts)
        print(f"JSON report written to {args.json}")

    if args.fail_on_critical and any(a.severity == "CRITICAL" for a in alerts):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
