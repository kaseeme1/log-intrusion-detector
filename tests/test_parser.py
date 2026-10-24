from datetime import datetime
from pathlib import Path

import pytest

from detector.parser import LoginEvent, parse_file, parse_line

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "auth.log"


def test_failed_password():
    line = "Oct 24 14:02:11 web01 sshd[2231]: Failed password for root from 203.0.113.45 port 52344 ssh2"
    assert parse_line(line) == LoginEvent(
        timestamp=datetime(2026, 10, 24, 14, 2, 11),
        ip="203.0.113.45",
        username="root",
        success=False,
        invalid_user=False,
    )


def test_failed_password_invalid_user():
    line = "Oct 24 14:02:15 web01 sshd[2232]: Failed password for invalid user admin from 203.0.113.45 port 52350 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.username == "admin"
    assert event.invalid_user is True
    assert event.success is False


def test_accepted_password():
    line = "Oct 24 14:05:01 web01 sshd[2240]: Accepted password for kaseem from 198.51.100.7 port 50111 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.username == "kaseem"
    assert event.ip == "198.51.100.7"
    assert event.success is True


def test_accepted_publickey():
    line = "Oct 24 14:06:44 web01 sshd[2241]: Accepted publickey for deploy from 198.51.100.8 port 50222 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.success is True
    assert event.username == "deploy"


def test_single_digit_day_is_space_padded():
    line = "Oct  5 03:04:05 web01 sshd[99]: Failed password for root from 192.0.2.1 port 4000 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.timestamp == datetime(2026, 10, 5, 3, 4, 5)


def test_year_argument_is_used():
    line = "Jan  1 00:00:01 web01 sshd[1]: Failed password for root from 192.0.2.1 port 4000 ssh2"
    event = parse_line(line, year=2025)
    assert event is not None
    assert event.timestamp.year == 2025


def test_different_hostname():
    line = "Oct 24 14:02:11 db-prod-02 sshd[2231]: Failed password for root from 203.0.113.45 port 52344 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.ip == "203.0.113.45"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "Oct 24 06:00:00 web01 CRON[6957]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Oct 24 12:40:00 web01 sshd[6280]: Invalid user admin from 192.0.2.77 port 37302",
        "Oct 24 12:40:01 web01 sshd[6280]: Connection closed by authenticating user admin 192.0.2.77 port 37302 [preauth]",
        "Oct 24 15:20:59 web01 sshd[9893]: Received disconnect from 203.0.113.99 port 47896:11: disconnected by user",
        "Oct 24 15:08:59 web01 sudo:   deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id",
        "Oct 24 14:05:01 web01 sshd[2240]: pam_unix(sshd:session): session opened for user kaseem(uid=1000) by (uid=0)",
        "this is not a log line at all",
    ],
)
def test_noise_lines_return_none(line):
    assert parse_line(line) is None


def test_parse_sample_file():
    events = parse_file(SAMPLE_LOG)

    brute = [e for e in events if e.ip == "203.0.113.45"]
    assert len(brute) == 40
    assert all(not e.success for e in brute)

    break_in = [e for e in events if e.ip == "203.0.113.99"]
    assert sum(not e.success for e in break_in) == 7
    assert sum(e.success for e in break_in) == 1

    assert events == sorted(events, key=lambda e: e.timestamp)
