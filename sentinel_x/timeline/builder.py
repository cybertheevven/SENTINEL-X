"""Attack timeline. A phase appears ONLY if a finding supports it."""
from __future__ import annotations

from sentinel_x.core.models import Finding

PHASE_OF = {
    "scanner_user_agent": "Reconnaissance",
    "content_enumeration": "Reconnaissance",
    "sensitive_path_access": "Reconnaissance",
    "sql_injection_attempt": "Initial Access / Exploitation",
    "path_traversal_attempt": "Initial Access / Exploitation",
    "possible_web_shell": "Execution / Persistence indicator",
    "script_in_upload_dir": "Execution / Persistence indicator",
    "bruteforce_login_attempts": "Authentication",
    "possible_login_success_after_failures": "Authentication",
    "ssh_user_enumeration": "Reconnaissance",
    "ssh_bruteforce_attempts": "Authentication",
    "ssh_login_success_after_failures": "Confirmed Access",
    "ssh_root_login": "Confirmed Access",
}
ORDER = ["Reconnaissance", "Initial Access / Exploitation", "Authentication", "Confirmed Access",
         "Execution / Persistence indicator"]


def build(findings: list[Finding]) -> list[dict]:
    rows = []
    for f in sorted(findings, key=lambda x: (x.timestamp, x.id)):
        phase = PHASE_OF.get(f.type)
        if not phase:
            continue
        rows.append({"timestamp": f.timestamp.isoformat(), "phase": phase, "finding_id": f.id,
                     "type": f.type, "ip": f.ip, "severity": f.severity,
                     "confidence": f.confidence, "classification": f.classification,
                     "evidence_id": f.evidence_id, "line": f.line,
                     "summary": f.description.split(".")[0] + "."})
    return rows


def phases_present(rows: list[dict]) -> list[str]:
    present = {r["phase"] for r in rows}
    return [p for p in ORDER if p in present]
