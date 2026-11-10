"""Initial access assessment. Conservative: says 'Undetermined' without evidence."""
from __future__ import annotations

from sentinel_x.core.models import Finding

EXPLOIT_TYPES = {"sql_injection_attempt", "path_traversal_attempt", "possible_web_shell"}
AUTH_TYPES = {"possible_login_success_after_failures", "ssh_login_success_after_failures"}
LABELS = {
    "sql_injection_attempt": "Exploitation of a web application (SQL injection)",
    "path_traversal_attempt": "Exploitation of a web application (path traversal)",
    "possible_web_shell": "Web shell interaction (implies earlier code execution/upload)",
    "possible_login_success_after_failures": "Credential guessing / brute force followed by apparent login",
    "ssh_login_success_after_failures": "Credential guessing against SSH followed by a logged successful login",
}
MISSING = [
    "SSH / system authentication logs (auth.log, secure)",
    "Application and database logs (to confirm exploit success)",
    "File integrity data or reference hashes (new/modified files)",
    "Process, cron and network-flow records (post-exploitation activity)",
]


def _confirmed(findings):
    return [{"finding_id": f.id, "timestamp": f.timestamp.isoformat(), "ip": f.ip, "user": f.details.get("user"),
             "evidence_id": f.evidence_id, "line": f.line}
            for f in findings if f.type == "ssh_login_success_after_failures"]


def assess(findings: list[Finding], sources: set[str] | None = None) -> dict:
    missing = [m for m in MISSING if not (sources and "auth" in sources and m.startswith("SSH"))]
    cands = [f for f in findings if f.type in EXPLOIT_TYPES | AUTH_TYPES]
    if not cands:
        return {"status": "Undetermined", "summary": "Initial Access: Undetermined",
                "hypothesis": None, "confidence": "Insufficient Evidence", "classification": "Unknown",
                "first_suspicious_event": None, "supporting_findings": [], "contradicting_evidence": [],
                "confirmed_access": [], "missing_evidence": missing}
    first = min(cands, key=lambda f: f.timestamp)
    same_ip = [f for f in cands if f.ip == first.ip]
    types = {f.type for f in same_ip}
    # Corroboration: more than one independent indicator from the same IP.
    corroborated = len(types) >= 2 or any(
        f.type == "cross_source_correlation" and f.ip == first.ip for f in findings)
    confidence = "Medium Confidence" if corroborated else "Low Confidence"
    contradicting = []
    ok_status = [f for f in same_ip if 200 <= int(f.details.get("status", 0)) < 300]
    if not ok_status and first.type in EXPLOIT_TYPES:
        contradicting.append("No 2xx response recorded for the exploit-like requests from this IP.")
    return {
        "status": "Hypothesis",
        "summary": f"Most likely initial access (hypothesis): {LABELS[first.type]} from {first.ip}",
        "hypothesis": LABELS[first.type],
        "confidence": confidence,
        "classification": "Inferred",
        "first_suspicious_event": {"finding_id": first.id, "timestamp": first.timestamp.isoformat(),
                                   "ip": first.ip, "target": first.details.get("path"),
                                   "evidence_id": first.evidence_id, "line": first.line},
        "supporting_findings": [f.id for f in same_ip],
        "confirmed_access": _confirmed(findings),
        "contradicting_evidence": contradicting,
        "missing_evidence": missing,
    }
