"""
Detection rules. Each rule looks at the list of LoginEvents and returns Alerts.

Rule 1  brute_force                 HIGH
    One IP fails to log in `threshold` or more times within `window`.
    Example: 203.0.113.45 fails 30 times in 2 minutes trying "root".

Rule 2  password_spray              HIGH
    One IP fails against `min_users` or more DIFFERENT usernames within `window`.
    Attackers do this to avoid lockouts: try one common password on many accounts.

Rule 3  success_after_failures      CRITICAL
    One IP fails `min_failures` or more times within `window`, and then a login
    from that same IP SUCCEEDS inside that window. This could mean they guessed
    the password and are now inside. It's the scariest alert.

"Within the window" includes the edge: if the window is 10 minutes, an event
exactly 10:00 after the first one still counts (use <=, not <).

Every rule should produce AT MOST ONE alert per IP (we don't want 30 duplicate
alerts for the same attacker). The alert's count, first_seen and last_seen
should describe the burst of activity that triggered it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from detector.parser import LoginEvent

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Alert:
    rule: str            # "brute_force", "password_spray", or "success_after_failures"
    severity: str        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    ip: str
    count: int           # how many failed attempts are in the triggering burst
    first_seen: datetime
    last_seen: datetime
    message: str
    usernames: list[str] = field(default_factory=list)  # sorted, unique usernames involved

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "usernames": self.usernames,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# YOUR CODE (Kaseem): write the three rules below
# ---------------------------------------------------------------------------
# A plan that works for all three ("sliding window"):
#   1. Group events by IP. A dict like {ip: [events...]} is perfect.
#      (collections.defaultdict(list) makes this easy.)
#   2. For each IP, keep only the events you care about (e.g. failures), in
#      time order.
#   3. Slide a window across them: for each event i, find how many events
#      happen between event i's time and event i's time + window.
#      Two pointers (a `start` and an `end` index) is the classic way.
#   4. If the count reaches the threshold, make ONE Alert for that IP and
#      move on to the next IP.
#
# Run the tests with:  pytest tests/test_rules.py -v


def detect_brute_force(
    events: list[LoginEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:
    """Flag IPs with `threshold`+ failed logins inside `window`. Severity HIGH.

    count      = number of failures in the BIGGEST burst you found for that IP
    first_seen = time of the first failure in that burst
    last_seen  = time of the last failure in that burst
    usernames  = sorted unique usernames tried in that burst
    """
    raise NotImplementedError("Kaseem: write detect_brute_force")


def detect_password_spray(
    events: list[LoginEvent],
    min_users: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:
    """Flag IPs that fail against `min_users`+ DIFFERENT usernames inside `window`. Severity HIGH.

    count      = number of failures in that burst
    usernames  = sorted unique usernames tried in that burst
    """
    raise NotImplementedError("Kaseem: write detect_password_spray")


def detect_success_after_failures(
    events: list[LoginEvent],
    min_failures: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:
    """Flag a SUCCESSFUL login preceded by `min_failures`+ failures from the
    same IP within `window` before it. Severity CRITICAL.

    count      = number of failures in the window before the success
    first_seen = time of the first of those failures
    last_seen  = time of the successful login
    usernames  = sorted unique usernames involved (failed ones + the one that worked)
    message    = should mention which username was logged into
    """
    raise NotImplementedError("Kaseem: write detect_success_after_failures")


# ---------------------------------------------------------------------------
# Provided: runs every rule and sorts the results, most severe first
# ---------------------------------------------------------------------------
def run_all_rules(events: list[LoginEvent]) -> list[Alert]:
    alerts = (
        detect_success_after_failures(events)
        + detect_brute_force(events)
        + detect_password_spray(events)
    )
    alerts.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 99), a.first_seen, a.ip))
    return alerts
