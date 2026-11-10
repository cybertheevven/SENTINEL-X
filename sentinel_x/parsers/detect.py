"""Format sniffing: decide which parser an evidence file needs."""
from __future__ import annotations

from sentinel_x.parsers import auth, web


def sniff(path, limit: int = 300) -> str:
    """Return 'web', 'auth', 'empty' or 'unknown'."""
    total = w = a = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            total += 1
            if web.LINE_RE.match(line.strip()):
                w += 1
            elif auth.looks_like_syslog(line):
                a += 1
            if total >= limit:
                break
    if total == 0:
        return "empty"
    if w / total >= 0.3 and w >= a:
        return "web"
    if a / total >= 0.3:
        return "auth"
    return "unknown"
