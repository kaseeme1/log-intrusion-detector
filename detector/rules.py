"""Detection rules for suspicious SSH login activity."""

from __future__ import annotations

from asyncio import events
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from detector.parser import LoginEvent

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    message: str
    usernames: list[str] = field(default_factory=list)

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


def detect_brute_force(
    events: list[LoginEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:

    alerts = []
    failures_by_ip = {}

    for event in events:
        if event.success:
            continue
        failures_by_ip.setdefault(event.ip, []).append(event)

    for ip, failures in failures_by_ip.items():
        best_count = 0
        best_start = None

        for start in failures:
            count = 0

            for other in failures:
                if timedelta(0) <= other.timestamp - start.timestamp <= window:
                    count += 1
            if count > best_count:
                best_count = count
                best_start = start

        if best_count >= threshold:
            usernames = sorted({f.username for f in failures if timedelta(0) <= f.timestamp - best_start.timestamp <= window})
            alert = Alert(
                rule="brute_force",
                severity="HIGH",
                ip=ip,
                count=best_count,
                first_seen=best_start.timestamp,
                last_seen=max(f.timestamp for f in failures if timedelta(0) <= f.timestamp - best_start.timestamp <= window),
                message=f"Detected {best_count} failed login attempts from IP {ip} within {window}.",
                usernames=usernames,
            )
            alerts.append(alert)

    return alerts


def detect_password_spray(
    events: list[LoginEvent],
    min_users: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]: 
        alerts = []
        failures_by_ip = {}
    
        for event in events:
            if event.success:
                continue
            failures_by_ip.setdefault(event.ip, []).append(event)
    
        for ip, failures in failures_by_ip.items():
            best_count = 0
            best_start = None
            best_users = 0

            for start in failures:
                count = 0
                users = set()
    
                for other in failures:
                    if timedelta(0) <= other.timestamp - start.timestamp <= window:
                        count += 1
                        users.add(other.username)
                if len(users) > best_users:
                    best_users = len(users)
                    best_count = count
                    best_start = start
    
            if best_users >= min_users:
                usernames = sorted({f.username for f in failures if timedelta(0) <= f.timestamp - best_start.timestamp <= window})
                alert = Alert(
                    rule="password_spray",
                    severity="HIGH",
                    ip=ip,
                    count=best_users,
                    first_seen=best_start.timestamp,
                    last_seen=max(f.timestamp for f in failures if timedelta(0) <= f.timestamp - best_start.timestamp <= window),
                    message = f"{best_users} different usernames tried from IP {ip} within {window}.",
                    usernames=usernames,
                )
                alerts.append(alert)
    
        return alerts


def detect_success_after_failures(
    events: list[LoginEvent],
    min_failures: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:
    alerts = []
    events_by_ip = {}

    for event in events:
        events_by_ip.setdefault(event.ip, []).append(event)

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)

        for success in ip_events:
            if not success.success:
                continue

            window_failures = []
            for other in ip_events:
                if not other.success and timedelta(0) <= success.timestamp - other.timestamp <= window:
                    window_failures.append(other)
            count = len(window_failures)

            if count >= min_failures:
                usernames = sorted({f.username for f in window_failures} | {success.username})
                alert = Alert(
                    rule="success_after_failures",
                    severity="CRITICAL",
                    ip=ip,
                    count=count,
                    first_seen=window_failures[0].timestamp,
                    last_seen=success.timestamp,
                    message=f"Logged in as {success.username} after {count} failed attempts from {ip}.",
                    usernames=usernames,
                )
                alerts.append(alert)
                break

    return alerts


def run_all_rules(events: list[LoginEvent]) -> list[Alert]:
    alerts = (
        detect_success_after_failures(events)
        + detect_brute_force(events)
        + detect_password_spray(events)
    )
    alerts.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 99), a.first_seen, a.ip))
    return alerts
