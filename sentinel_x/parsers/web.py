"""Apache / Nginx access-log parser (Common & Combined Log Format)."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from sentinel_x.core.models import LogEvent

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str, evidence_id: str, file: str, lineno: int) -> LogEvent | None:
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], TS_FORMAT)
    except ValueError:
        return None
    size = 0 if m["size"] == "-" else int(m["size"])
    return LogEvent(
        evidence_id=evidence_id, file=file, line=lineno, ip=m["ip"], ts=ts,
        method=m["method"], path=m["path"], status=int(m["status"]), size=size,
        referer=m["referer"] or "", user_agent=m["ua"] or "", raw=line.rstrip("\n"),
    )


def parse_file(path: str | Path, evidence_id: str, file_label: str | None = None):
    """Returns (events, stats). Never raises on malformed lines."""
    label = file_label or Path(path).name
    events: list[LogEvent] = []
    total = blank = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                blank += 1
                continue
            total += 1
            ev = parse_line(line, evidence_id, label, lineno)
            if ev:
                events.append(ev)
    stats = {"evidence_id": evidence_id, "file": label, "lines": total,
             "parsed": len(events), "unparsed": total - len(events)}
    return events, stats
