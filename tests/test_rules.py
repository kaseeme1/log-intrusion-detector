from datetime import datetime, timedelta
from pathlib import Path

from detector.parser import LoginEvent, parse_file
from detector.rules import (
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    run_all_rules,
)

T0 = datetime(2026, 10, 24, 12, 0, 0)
SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "auth.log"


def fail(minutes: float, ip: str = "203.0.113.1", user: str = "root") -> LoginEvent:
    return LoginEvent(T0 + timedelta(minutes=minutes), ip, user, success=False)


def ok(minutes: float, ip: str = "203.0.113.1", user: str = "root") -> LoginEvent:
    return LoginEvent(T0 + timedelta(minutes=minutes), ip, user, success=True)


def test_brute_force_triggers_at_threshold():
    events = [fail(m) for m in (0, 1, 2, 3, 4)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == "brute_force"
    assert a.severity == "HIGH"
    assert a.ip == "203.0.113.1"
    assert a.count == 5
    assert a.first_seen == T0
    assert a.last_seen == T0 + timedelta(minutes=4)
    assert a.usernames == ["root"]


def test_brute_force_below_threshold():
    events = [fail(m) for m in (0, 1, 2, 3)]
    assert detect_brute_force(events) == []


def test_brute_force_too_spread_out():
    events = [fail(m) for m in (0, 3, 6, 9, 12)]
    assert detect_brute_force(events) == []


def test_brute_force_window_edge_is_inclusive():
    events = [fail(m) for m in (0, 1, 2, 3, 10)]
    assert len(detect_brute_force(events)) == 1


def test_brute_force_ignores_successful_logins():
    events = [fail(m) for m in (0, 1, 2, 3)] + [ok(4)]
    assert detect_brute_force(events) == []


def test_brute_force_one_alert_per_ip():
    events = [fail(m * 0.1) for m in range(30)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].count == 30


def test_brute_force_reports_biggest_burst():
    small = [fail(m) for m in (0, 1, 2, 3, 4, 5)]
    big = [fail(120 + m) for m in (0, 1, 2, 3, 4, 5, 6, 7, 8)]
    alerts = detect_brute_force(small + big)
    assert len(alerts) == 1
    assert alerts[0].count == 9
    assert alerts[0].first_seen == T0 + timedelta(minutes=120)


def test_brute_force_separate_ips():
    events = [fail(m, ip="203.0.113.1") for m in range(5)] + [fail(m, ip="203.0.113.2") for m in range(5)]
    assert {a.ip for a in detect_brute_force(events)} == {"203.0.113.1", "203.0.113.2"}


def test_brute_force_does_not_mix_ips():
    events = [fail(m, ip="203.0.113.1") for m in range(3)] + [fail(m, ip="203.0.113.2") for m in range(3)]
    assert detect_brute_force(events) == []


def test_brute_force_custom_threshold_and_window():
    events = [fail(m) for m in (0, 1, 2)]
    assert len(detect_brute_force(events, threshold=3, window=timedelta(minutes=2))) == 1
    assert detect_brute_force(events, threshold=3, window=timedelta(minutes=1)) == []


def test_brute_force_unsorted_input():
    events = [fail(m) for m in (4, 0, 3, 1, 2)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].first_seen == T0


def test_brute_force_usernames_sorted_unique():
    users = ["root", "admin", "root", "admin", "ubuntu"]
    events = [fail(i, user=u) for i, u in enumerate(users)]
    assert detect_brute_force(events)[0].usernames == ["admin", "root", "ubuntu"]


def test_spray_triggers_on_many_usernames():
    users = ["admin", "test", "oracle", "postgres", "ubuntu"]
    events = [fail(i, user=u) for i, u in enumerate(users)]
    alerts = detect_password_spray(events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == "password_spray"
    assert a.severity == "HIGH"
    assert a.count == 5
    assert a.usernames == sorted(users)


def test_spray_same_username_is_not_spray():
    events = [fail(i * 0.5, user="root") for i in range(10)]
    assert detect_password_spray(events) == []


def test_spray_too_few_usernames():
    events = [fail(i, user=u) for i, u in enumerate(["a", "b", "c", "d"])]
    assert detect_password_spray(events) == []


def test_spray_too_spread_out():
    events = [fail(i * 5, user=u) for i, u in enumerate(["a", "b", "c", "d", "e"])]
    assert detect_password_spray(events) == []


def test_spray_one_alert_per_ip():
    events = [fail(i * 0.2, user=f"user{i}") for i in range(20)]
    assert len(detect_password_spray(events)) == 1


def test_break_in_detected():
    events = [fail(m, user="deploy") for m in (0, 1, 2, 3, 4)] + [ok(5, user="deploy")]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == "success_after_failures"
    assert a.severity == "CRITICAL"
    assert a.count == 5
    assert a.first_seen == T0
    assert a.last_seen == T0 + timedelta(minutes=5)
    assert "deploy" in a.message


def test_break_in_not_enough_failures():
    events = [fail(m) for m in (0, 1, 2, 3)] + [ok(4)]
    assert detect_success_after_failures(events) == []


def test_normal_typo_is_fine():
    events = [fail(0, user="kaseem"), ok(0.2, user="kaseem")]
    assert detect_success_after_failures(events) == []


def test_break_in_success_too_late():
    events = [fail(m) for m in (0, 1, 2, 3, 4)] + [ok(30)]
    assert detect_success_after_failures(events) == []


def test_break_in_success_before_failures_does_not_count():
    events = [ok(0)] + [fail(m) for m in (1, 2, 3, 4, 5)]
    assert detect_success_after_failures(events) == []


def test_break_in_success_from_other_ip_does_not_count():
    events = [fail(m, ip="203.0.113.1") for m in range(5)] + [ok(5, ip="198.51.100.7")]
    assert detect_success_after_failures(events) == []


def test_break_in_only_counts_failures_inside_window():
    old = [fail(m) for m in (0, 1, 2)]
    recent = [fail(m) for m in (15, 16, 17, 18, 19)]
    alerts = detect_success_after_failures(old + recent + [ok(20)])
    assert len(alerts) == 1
    assert alerts[0].count == 5
    assert alerts[0].first_seen == T0 + timedelta(minutes=15)


def test_break_in_different_username_still_counts():
    events = [fail(m, user="root") for m in range(5)] + [ok(5, user="backup")]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    assert alerts[0].usernames == ["backup", "root"]
    assert "backup" in alerts[0].message


def test_break_in_one_alert_per_ip():
    events = [fail(m) for m in range(5)] + [ok(5), ok(6)]
    assert len(detect_success_after_failures(events)) == 1


def test_sample_log_finds_the_hidden_attacks():
    alerts = run_all_rules(parse_file(SAMPLE_LOG))
    found = {(a.rule, a.ip) for a in alerts}

    assert ("success_after_failures", "203.0.113.99") in found
    assert ("brute_force", "203.0.113.45") in found
    assert ("password_spray", "192.0.2.77") in found

    flagged_ips = {a.ip for a in alerts}
    assert "198.51.100.200" not in flagged_ips
    assert not any(ip.startswith("198.51.100.") for ip in flagged_ips)

    assert alerts[0].severity == "CRITICAL"
