"""Turns alerts into a readable terminal report and a JSON file."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from detector.parser import LoginEvent
from detector.rules import Alert

COLORS = {
    "CRITICAL": "\033[1;97;41m",  # bold white on red
    "HIGH": "\033[1;31m",         # bold red
    "MEDIUM": "\033[33m",         # yellow
    "LOW": "\033[36m",            # cyan
}
RESET = "\033[0m"


def _paint(text: str, severity: str, color: bool) -> str:
    if not color:
        return text
    return f"{COLORS.get(severity, '')}{text}{RESET}"


def summarize(events: list[LoginEvent]) -> dict:
    failures = [e for e in events if not e.success]
    return {
        "total_events": len(events),
        "successful_logins": sum(1 for e in events if e.success),
        "failed_logins": len(failures),
        "unique_ips": len({e.ip for e in events}),
        "top_failing_ips": Counter(e.ip for e in failures).most_common(5),
    }


def format_report(events: list[LoginEvent], alerts: list[Alert], color: bool = True) -> str:
    s = summarize(events)
    lines = [
        "=" * 64,
        "  LOG INTRUSION DETECTOR - REPORT",
        "=" * 64,
        f"  Login events analyzed : {s['total_events']}",
        f"  Successful logins     : {s['successful_logins']}",
        f"  Failed logins         : {s['failed_logins']}",
        f"  Unique source IPs     : {s['unique_ips']}",
        "",
    ]

    if s["top_failing_ips"]:
        lines.append("  Top failing IPs:")
        for ip, n in s["top_failing_ips"]:
            lines.append(f"    {ip:<18} {n:>5} failures")
        lines.append("")

    if not alerts:
        lines.append("  No suspicious activity detected.")
    else:
        lines.append(f"  ALERTS ({len(alerts)})")
        lines.append("-" * 64)
        for a in alerts:
            tag = _paint(f"[{a.severity}]", a.severity, color)
            lines.append(f"  {tag} {a.rule}  from {a.ip}")
            lines.append(f"      {a.message}")
            lines.append(
                f"      {a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S}"
                f"  |  {a.count} failed attempts"
            )
            if a.usernames:
                shown = ", ".join(a.usernames[:6])
                more = f" (+{len(a.usernames) - 6} more)" if len(a.usernames) > 6 else ""
                lines.append(f"      usernames: {shown}{more}")
            lines.append("")
    lines.append("=" * 64)
    return "\n".join(lines)


def write_json(path: str | Path, events: list[LoginEvent], alerts: list[Alert]) -> None:
    s = summarize(events)
    payload = {
        "summary": {**s, "top_failing_ips": [{"ip": ip, "failures": n} for ip, n in s["top_failing_ips"]]},
        "alerts": [a.to_dict() for a in alerts],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def should_use_color() -> bool:
    return sys.stdout.isatty()
