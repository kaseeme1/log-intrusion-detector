"""
Turns raw lines from a Linux auth log into structured LoginEvent objects.

A real auth.log is mostly noise (cron jobs, sudo, session messages).
We only care about SSH login attempts, which look like this:

    Oct 24 14:02:11 web01 sshd[2231]: Failed password for root from 203.0.113.45 port 52344 ssh2
    Oct 24 14:02:15 web01 sshd[2232]: Failed password for invalid user admin from 203.0.113.45 port 52350 ssh2
    Oct 24 14:05:01 web01 sshd[2240]: Accepted password for kaseem from 198.51.100.7 port 50111 ssh2
    Oct 24 14:06:44 web01 sshd[2241]: Accepted publickey for deploy from 198.51.100.8 port 50222 ssh2

Pieces of each line:
    "Oct 24 14:02:11"   -> when it happened (note: syslog leaves out the YEAR)
    "Failed"/"Accepted" -> did the login work?
    "password"/"publickey" -> how they tried to log in
    "invalid user"      -> optional; means that username doesn't exist on the server
    "root"              -> the username they tried
    "203.0.113.45"      -> the IP address it came from
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class LoginEvent:
    """One SSH login attempt pulled out of the log."""

    timestamp: datetime
    ip: str
    username: str
    success: bool
    invalid_user: bool = False  # True when the log says "invalid user"


# ---------------------------------------------------------------------------
# YOUR CODE (Kaseem): write parse_line
# ---------------------------------------------------------------------------
# Hints, step by step:
#   1. Write ONE regular expression that matches both "Failed ..." and
#      "Accepted ..." lines. Use named groups like (?P<ip>...) so you can pull
#      pieces out by name. Test it on the example lines at the top of this file.
#   2. If the line doesn't match, return None (it's noise like cron or sudo).
#   3. Build the timestamp with datetime.strptime. Syslog has no year, so glue
#      the `year` argument on first, e.g. f"{year} Oct 24 14:02:11" with the
#      format "%Y %b %d %H:%M:%S".
#      Watch out: single-digit days are padded with a SPACE ("Oct  5"), so
#      your regex needs to allow one or more spaces there.
#   4. success is True when the line says "Accepted".
#   5. invalid_user is True when the words "invalid user" appear.
#
# The tests in tests/test_parser.py tell you exactly what's expected.
# Run them with:  pytest tests/test_parser.py -v

LINE_PATTERN = re.compile(r"TODO")  # replace with your regex


def parse_line(line: str, year: int = 2026) -> LoginEvent | None:
    if not ("Failed" in line or "Accepted" in line):
        return None

    Data = line.strip();
    Parsed_Data = Data.split();

    username = Parsed_Data[8]
    ip = Parsed_Data[10]    

    Success = True if Parsed_Data[5] == "Accepted" else False

    invalid_user = True if Parsed_Data[8] == "invalid" else False

    if invalid_user:
        username = Parsed_Data[10]
        ip = Parsed_Data[12]
    else:
        username = Parsed_Data[8]
        ip = Parsed_Data[10]


    
    timestamp = datetime.strptime(f"{year} {Parsed_Data[0]} {Parsed_Data[1]} {Parsed_Data[2]}", "%Y %b %d %H:%M:%S")

    return LoginEvent(
        timestamp=timestamp,
        ip=ip,
        username=username,
        success=Success,
        invalid_user=invalid_user
    )


    


# ---------------------------------------------------------------------------
# Provided: reads a whole file using your parse_line
# ---------------------------------------------------------------------------
def parse_file(path: str | Path, year: int = 2026) -> list[LoginEvent]:
    """Read a log file and return every login event in time order."""
    events: list[LoginEvent] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line.rstrip("\n"), year=year)
            if event is not None:
                events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return events
