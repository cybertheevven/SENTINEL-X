from __future__ import annotations

import json
from pathlib import Path

from sentinel_x import __version__
from sentinel_x.core.case import Case
from sentinel_x.evidence.collector import EvidenceStore, utcnow

LIMITATIONS = [
    "Web access logs show requests and response codes only; they cannot prove that an exploit or login succeeded.",
    "An IP address does not identify a person. Geolocation and VPN/proxy status are not assessed in this version.",
    "Findings are rule-based and may include false positives or miss unknown techniques.",
    "Only Apache/Nginx access logs and SSH auth logs are analyzed in this version; other evidence types are listed as unsupported.",
    "Classic syslog timestamps have no year or timezone: the year comes from --year or the file modification time and times are treated as UTC.",
]


def collect(case: Case) -> dict:
    if not case.analysis_file.exists():
        raise FileNotFoundError("No analysis found. Run: sentinel-x analyze --case " + case.name)
    analysis = json.loads(case.analysis_file.read_text(encoding="utf-8"))
    ai = json.loads(case.ai_file.read_text(encoding="utf-8")) if case.ai_file.exists() else None
    return {
        "report_generated_at": utcnow(), "tool": f"SENTINEL-X {__version__}",
        "case": case.meta(), "evidence": EvidenceStore(case.dir).entries(),
        "analysis": analysis, "ai_investigation": ai, "limitations": LIMITATIONS,
    }


def write(case: Case, out: Path) -> Path:
    out.write_text(json.dumps(collect(case), indent=2), encoding="utf-8")
    return out
