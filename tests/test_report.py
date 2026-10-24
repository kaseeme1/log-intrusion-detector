import json
from datetime import datetime

from detector.__main__ import main
from detector.parser import LoginEvent
from detector.report import format_report, summarize, write_json
from detector.rules import Alert

T = datetime(2026, 10, 24, 12, 0, 0)
EVENTS = [
    LoginEvent(T, "203.0.113.1", "root", success=False),
    LoginEvent(T, "203.0.113.1", "root", success=False),
    LoginEvent(T, "198.51.100.7", "kaseem", success=True),
]
ALERT = Alert(
    rule="brute_force",
    severity="HIGH",
    ip="203.0.113.1",
    count=2,
    first_seen=T,
    last_seen=T,
    message="2 failed logins in 10 minutes",
    usernames=["root"],
)


def test_summarize_counts():
    s = summarize(EVENTS)
    assert s["total_events"] == 3
    assert s["failed_logins"] == 2
    assert s["successful_logins"] == 1
    assert s["unique_ips"] == 2
    assert s["top_failing_ips"][0] == ("203.0.113.1", 2)


def test_report_shows_alert():
    text = format_report(EVENTS, [ALERT], color=False)
    assert "[HIGH] brute_force" in text
    assert "203.0.113.1" in text
    assert "\033[" not in text


def test_report_without_alerts():
    assert "No suspicious activity detected." in format_report(EVENTS, [], color=False)


def test_json_output(tmp_path):
    out = tmp_path / "report.json"
    write_json(out, EVENTS, [ALERT])
    data = json.loads(out.read_text())
    assert data["summary"]["failed_logins"] == 2
    assert data["alerts"][0]["ip"] == "203.0.113.1"
    assert data["alerts"][0]["first_seen"] == "2026-10-24T12:00:00"


def test_cli_missing_file_returns_1(tmp_path):
    assert main([str(tmp_path / "nope.log")]) == 1
