"""Defensive remediation guidance derived from finding types (generic; validate per environment)."""
from __future__ import annotations

PRIORITY_ORDER = {"Immediate": 0, "High": 1, "Medium": 2}

PRESERVE = ("Immediate", "Preserve evidence first: snapshot disk/memory and keep the original logs before any cleanup.")

RECS: dict[str, list[tuple[str, str]]] = {
    "sql_injection_attempt": [("High", "Review the targeted endpoint; use parameterized queries and input validation; add a WAF rule."),
                              ("High", "Review database logs for the same timeframe to see whether queries executed.")],
    "path_traversal_attempt": [("High", "Normalize and validate file parameters; restrict the web user's filesystem access (least privilege).")],
    "possible_web_shell": [("Immediate", "Isolate the host from the network if a web shell is suspected; locate and hash the file, do not execute it."),
                           ("Immediate", "Disable script execution in upload directories; compare web root against a clean baseline."),
                           ("High", "Rotate secrets reachable by the web server user (DB passwords, API keys).")],
    "script_in_upload_dir": [("High", "Verify the origin of scripts inside upload directories and block script execution there.")],
    "bruteforce_login_attempts": [("High", "Enable rate limiting / lockout and MFA on the login endpoint.")],
    "possible_login_success_after_failures": [("Immediate", "Force a password reset for the affected account(s) and review activity after the login time.")],
    "ssh_bruteforce_attempts": [("High", "Disable SSH password authentication (key-only), add fail2ban or equivalent rate limiting."),
                                ("Medium", "Restrict SSH exposure by source IP / VPN.")],
    "ssh_user_enumeration": [("Medium", "Remove unused accounts and restrict allowed users with AllowUsers/AllowGroups.")],
    "ssh_login_success_after_failures": [("Immediate", "Terminate the session, reset the credentials and review ~/.ssh/authorized_keys, cron jobs, new users and services."),
                                         ("High", "Review commands and file changes made by that account after the login time (shell history, auditd).")],
    "ssh_root_login": [("High", "Set PermitRootLogin no and use sudo from named accounts.")],
    "content_enumeration": [("Medium", "Rate-limit or block the source after preserving evidence; verify no sensitive files are exposed.")],
    "scanner_user_agent": [("Medium", "Block known scanner User-Agents at the edge and monitor the same IP for follow-up activity.")],
    "sensitive_path_access": [("Medium", "Remove backups, VCS folders and config files from the web root; restrict admin tools by IP.")],
    "cross_source_correlation": [("Immediate", "Treat as a potential compromise: extend the investigation to other hosts and block the IP after preserving evidence (the IP may be shared).")],
}


def build(findings: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    serious = any(f["severity"] in ("High", "Critical") for f in findings)
    if serious:
        merged[PRESERVE[1]] = {"priority": PRESERVE[0], "action": PRESERVE[1], "findings": []}
    for f in findings:
        for prio, action in RECS.get(f["type"], []):
            entry = merged.setdefault(action, {"priority": prio, "action": action, "findings": []})
            if PRIORITY_ORDER[prio] < PRIORITY_ORDER[entry["priority"]]:
                entry["priority"] = prio
            if f["id"] not in entry["findings"]:
                entry["findings"].append(f["id"])
    out = sorted(merged.values(), key=lambda r: (PRIORITY_ORDER[r["priority"]], r["action"] != PRESERVE[1], r["action"]))
    return out
