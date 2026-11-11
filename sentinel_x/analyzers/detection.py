"""Rule-based detection on parsed web events.

Every finding is tied to an evidence ID + line and carries severity (impact)
and confidence (strength of evidence) as SEPARATE fields.
A request that LOOKS like an attack is Observed; whether it SUCCEEDED is Unknown
unless other evidence shows it.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta
from urllib.parse import unquote

from sentinel_x.core.models import Finding, LogEvent

SQLI_RE = re.compile(
    r"(union(\s|\+|/\*.*?\*/)+(all\s+)?select|information_schema|\b(or|and)\s+\d+\s*=\s*\d+|"
    r"'\s*or\s*'?\d*'?\s*=\s*'?\d|sleep\s*\(\s*\d+|benchmark\s*\(|;\s*drop\s+table|load_file\s*\()",
    re.I,
)
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)", re.I)
WEBSHELL_PARAM_RE = re.compile(
    r"(\b(cmd|exec|command|shell)=|eval\(|base64_decode|system\(|passthru\(|shell_exec)", re.I)
WEBSHELL_NAME_RE = re.compile(r"/(c99|r57|wso|b374k|shell|cmd|webshell)[^/]*\.(php|jsp|asp|aspx)", re.I)
SCRIPT_EXT_RE = re.compile(r"\.(php\d?|phtml|jsp|aspx?)(\?|$)", re.I)
SENSITIVE_RE = re.compile(
    r"(/\.env|/\.git(/|$)|/\.svn|/wp-config|/phpmyadmin|/server-status|/\.ssh|/id_rsa|"
    r"\.sql(\?|$)|\.bak(\?|$)|/backup)", re.I)
LOGIN_RE = re.compile(r"(wp-login|xmlrpc|login|signin|/admin)", re.I)
SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|zgrab|nuclei|acunetix|nessus)", re.I)

DEFAULTS = {
    "bruteforce_threshold": 5,     # failed logins ...
    "bruteforce_window_s": 300,    # ... within this window, per IP
    "enum_404_threshold": 15,      # 404s ...
    "enum_404_window_s": 60,       # ... within this window, per IP
}


def finalize(raw: list[Finding]) -> list[Finding]:
    """Sort chronologically and assign sequential finding IDs."""
    findings = sorted(raw, key=lambda f: (f.timestamp, f.evidence_id, f.line or 0, f.type))
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:04d}"
    return findings


def decode(path: str) -> str:
    return unquote(unquote(path)).replace("+", " ")


def _first_window(times, threshold: int, window: timedelta):
    """Index of first start i with times[i+threshold-1]-times[i] <= window, else None."""
    for i in range(len(times) - threshold + 1):
        if times[i + threshold - 1] - times[i] <= window:
            return i
    return None


class Detector:
    def __init__(self, config: dict | None = None):
        self.cfg = {**DEFAULTS, **(config or {})}
        for key in ("bruteforce_threshold", "enum_404_threshold",
                    "bruteforce_window_s", "enum_404_window_s"):
            value = self.cfg[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{key} must be a positive integer")
        self._raw: list[Finding] = []

    def _add(self, ev: LogEvent, ftype: str, severity: str, confidence: str,
             classification: str, description: str, **details) -> None:
        details.update({"path": ev.path, "status": ev.status, "user_agent": ev.user_agent,
                        "method": ev.method})
        self._raw.append(Finding("", ftype, ev.ts, ev.evidence_id, ev.file, ev.line, ev.ip,
                                 severity, confidence, classification, description, details))

    # ------------------------------------------------------------------
    def run(self, events: list[LogEvent]) -> list[Finding]:
        return finalize(self.detect(events))

    def detect(self, events: list[LogEvent]) -> list[Finding]:
        self._raw = []
        events = sorted(events, key=lambda e: (e.ts, e.evidence_id, e.line))
        seen_ua: set[tuple[str, str]] = set()
        for ev in events:
            self._per_event(ev, seen_ua)
        self._bruteforce(events)
        self._enumeration(events)
        return list(self._raw)

    def _per_event(self, ev: LogEvent, seen_ua: set) -> None:
        path = decode(ev.path)
        ok = 200 <= ev.status < 300
        note = (f" Response status {ev.status} alone does not prove the attempt succeeded."
                if ok else f" Response status {ev.status} suggests it did not succeed (not proven).")

        if SQLI_RE.search(path):
            self._add(ev, "sql_injection_attempt", "High", "Medium Confidence", "Observed",
                      "Request contains SQL injection patterns." + note)
        if TRAVERSAL_RE.search(path):
            conf = "High Confidence" if re.search(r"/etc/(passwd|shadow)", path, re.I) else "Medium Confidence"
            self._add(ev, "path_traversal_attempt", "High", conf, "Observed",
                      "Request contains path traversal patterns." + note)
        is_script = bool(SCRIPT_EXT_RE.search(ev.path))
        if is_script and (WEBSHELL_PARAM_RE.search(path) or WEBSHELL_NAME_RE.search(path)):
            sev = "Critical" if ok else "High"
            self._add(ev, "possible_web_shell", sev, "Medium Confidence" if ok else "Low Confidence",
                      "Observed" if not ok else "Inferred",
                      "Script request with command-execution parameters or web-shell-like name." + note)
        elif is_script and re.search(r"/(uploads?|files|images|tmp)/", path, re.I) and ev.method == "POST":
            self._add(ev, "script_in_upload_dir", "Medium", "Low Confidence", "Inferred",
                      "POST to a script inside an upload-like directory; verify the file's origin.")
        if SENSITIVE_RE.search(path):
            self._add(ev, "sensitive_path_access", "Medium" if ok else "Low",
                      "Medium Confidence", "Observed",
                      "Request targets a sensitive path (config, VCS, backup, admin tooling)." + note)
        m = SCANNER_UA_RE.search(ev.user_agent)
        if m and (ev.ip, m.group(1).lower()) not in seen_ua:
            seen_ua.add((ev.ip, m.group(1).lower()))
            self._add(ev, "scanner_user_agent", "Medium", "High Confidence", "Observed",
                      f"User-Agent matches known scanning/attack tool '{m.group(1).lower()}' (first occurrence).")

    def _bruteforce(self, events: list[LogEvent]) -> None:
        window = timedelta(seconds=self.cfg["bruteforce_window_s"])
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for ev in events:
            if ev.method == "POST" and LOGIN_RE.search(decode(ev.path)):
                by_ip[ev.ip].append(ev)
        for ip, evs in by_ip.items():
            fails = [e for e in evs if e.status in (401, 403)]
            idx = _first_window([e.ts for e in fails], self.cfg["bruteforce_threshold"], window)
            if idx is None:
                continue
            first = fails[idx]
            last_fail = fails[-1]
            self._add(first, "bruteforce_login_attempts", "High", "High Confidence", "Observed",
                      f"{len(fails)} failed login responses (401/403) from one IP; "
                      f">= {self.cfg['bruteforce_threshold']} within {self.cfg['bruteforce_window_s']}s.",
                      failed_count=len(fails), last_failure=last_fail.ts.isoformat())
            for e in evs:
                if e.ts > last_fail.ts and e.status in (200, 302, 303):
                    conf = "Medium Confidence" if e.status in (302, 303) else "Low Confidence"
                    self._add(e, "possible_login_success_after_failures", "High", conf, "Inferred",
                              f"Login-path POST returned {e.status} after {len(fails)} failures from the "
                              "same IP. Web logs cannot confirm authentication; verify in application/auth logs.",
                              failed_before=len(fails))
                    break

    def _enumeration(self, events: list[LogEvent]) -> None:
        window = timedelta(seconds=self.cfg["enum_404_window_s"])
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for ev in events:
            if ev.status == 404:
                by_ip[ev.ip].append(ev)
        for ip, evs in by_ip.items():
            idx = _first_window([e.ts for e in evs], self.cfg["enum_404_threshold"], window)
            if idx is not None:
                self._add(evs[idx], "content_enumeration", "Medium", "High Confidence", "Observed",
                          f"{len(evs)} HTTP 404 responses from one IP; >= {self.cfg['enum_404_threshold']} "
                          f"within {self.cfg['enum_404_window_s']}s (directory/content discovery pattern).",
                          total_404=len(evs))


def compute_stats(events: list[LogEvent]) -> dict:
    if not events:
        return {"total_requests": 0, "unique_ips": 0, "first_event": None, "last_event": None,
                "status_counts": {}, "top_ips": [], "top_paths": []}
    ips = Counter(e.ip for e in events)
    paths = Counter(e.path.split("?")[0] for e in events)
    status = Counter(str(e.status) for e in events)
    ts = [e.ts for e in events]
    return {"total_requests": len(events), "unique_ips": len(ips),
            "first_event": min(ts).isoformat(), "last_event": max(ts).isoformat(),
            "status_counts": dict(sorted(status.items())),
            "top_ips": ips.most_common(10), "top_paths": paths.most_common(10)}
