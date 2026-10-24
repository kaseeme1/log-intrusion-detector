"""Parse SSH login attempts from Linux auth logs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    ip: str
    username: str
    success: bool
    invalid_user: bool = False


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


def parse_file(path: str | Path, year: int = 2026) -> list[LoginEvent]:
    events: list[LoginEvent] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line.rstrip("\n"), year=year)
            if event is not None:
                events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return events
