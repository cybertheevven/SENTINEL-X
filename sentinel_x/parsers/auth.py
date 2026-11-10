"""SSH authentication log parser (Debian/Kali auth.log, RHEL secure, rsyslog ISO format).

Classic syslog timestamps carry no year/timezone: the year is taken from --year, else from
the file's modification time, and the time is treated as UTC. This is documented in the report.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel_x.core.models import AuthEvent

CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[\d+\])?: (?P<msg>.*)$")
ISO = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?) (?P<host>\S+) "
    r"(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[\d+\])?: (?P<msg>.*)$")
FAILED = re.compile(r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from "
                    r"(?P<ip>[0-9a-fA-F:.]+) port \d+")
ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")


def looks_like_syslog(line: str) -> bool:
    s = line.strip()
    return bool(CLASSIC.match(s) or ISO.match(s))


def parse_header(line: str, year: int, ref: datetime | None):
    """Return (ts, host, proc, msg) or None."""
    s = line.strip()
    m = CLASSIC.match(s)
    if m:
        try:
            ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        ts = ts.replace(tzinfo=timezone.utc)
        if ref is not None and ts > ref + timedelta(days=1):   # Dec log read in January etc.
            try:
                ts = ts.replace(year=ts.year - 1)
            except ValueError:
                return None
        return ts, m["host"], m["proc"], m["msg"]
    m = ISO.match(s)
    if m:
        try:
            ts = datetime.fromisoformat(m["iso"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts, m["host"], m["proc"], m["msg"]
    return None


def parse_line(line, evidence_id, file, lineno, year, ref=None) -> AuthEvent | None:
    h = parse_header(line, year, ref)
    if not h:
        return None
    ts, host, proc, msg = h
    if not proc.startswith("sshd"):
        return None
    common = dict(evidence_id=evidence_id, file=file, line=lineno, ts=ts, host=host, raw=line.rstrip("\n"))
    m = FAILED.search(msg)
    if m:
        return AuthEvent(kind="failed", user=m["user"], ip=m["ip"], method=m["method"],
                         invalid_user=bool(m["invalid"]), **common)
    m = ACCEPTED.search(msg)
    if m:
        return AuthEvent(kind="accepted", user=m["user"], ip=m["ip"], method=m["method"],
                         invalid_user=False, **common)
    m = INVALID.search(msg)
    if m:
        return AuthEvent(kind="invalid_user", user=m["user"], ip=m["ip"], method="-",
                         invalid_user=True, **common)
    return None


def parse_file(path: str | Path, evidence_id: str, file_label: str | None = None, year: int | None = None):
    path = Path(path)
    label = file_label or path.name
    ref = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    year = year or ref.year
    ref_arg = None if year != ref.year else ref
    events, total, recognized = [], 0, 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            total += 1
            if looks_like_syslog(line):
                recognized += 1
            ev = parse_line(line, evidence_id, label, lineno, year, ref_arg)
            if ev:
                events.append(ev)
    return events, {"evidence_id": evidence_id, "file": label, "lines": total, "parsed": recognized,
                    "unparsed": total - recognized, "events": len(events), "year_assumed": year}
