"""Cross-source correlation (web <-> SSH). Always Inferred: shared IPs/NAT are possible."""
from __future__ import annotations

from sentinel_x.core.models import Finding

WEB_ATTACK = {"sql_injection_attempt", "path_traversal_attempt", "possible_web_shell",
              "bruteforce_login_attempts", "possible_login_success_after_failures",
              "content_enumeration", "scanner_user_agent"}
SSH_SUCCESS = {"ssh_login_success_after_failures"}


def correlate(findings: list[Finding]) -> list[Finding]:
    web: dict[str, list[Finding]] = {}
    ssh: dict[str, list[Finding]] = {}
    for f in findings:
        if f.type in WEB_ATTACK:
            web.setdefault(f.ip, []).append(f)
        elif f.type in SSH_SUCCESS:
            ssh.setdefault(f.ip, []).append(f)
    out = []
    for ip in sorted(set(web) & set(ssh)):
        w = min(web[ip], key=lambda f: f.timestamp)
        s = min(ssh[ip], key=lambda f: f.timestamp)
        out.append(Finding(
            "", "cross_source_correlation", s.timestamp, s.evidence_id, s.file, s.line, ip, "High",
            "Medium Confidence", "Inferred",
            f"IP {ip} appears in web attack activity (first: {w.evidence_id}:{w.line}, {w.type}) and also has a "
            f"logged successful SSH login ({s.evidence_id}:{s.line}). The same actor is plausible but not proven "
            "(shared or NAT addresses are possible).",
            {"web_first": f"{w.evidence_id}:{w.line}", "ssh_success": f"{s.evidence_id}:{s.line}", "source": "correlation"}))
    return out
